import argparse
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from . import __version__, usb
from .common import (
    CASES, CLI, CLAM, DATA, DEFINITIONS, STATE, CheckError, case_path,
    clam_args, command, read_json, write_json,
)
from .scanner import digest_image, safe_label, signature_status

MIN_FREE = 384 * 1024 * 1024
FINAL_PHASES = {"done", "failed", "refused", "held", "timeout"}


@contextmanager
def lock(wait=False):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / "lock").open("a") as fd:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError as error:
            raise CheckError("A USB Checker job is running.") from error
        yield


def status(path, **changes):
    file = path / "status.json"
    current = read_json(file) if file.is_file() else {"case": path.name}
    if changes:
        current.update(changes)
        write_json(file, current)
    return current


def new_case():
    CASES.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = CASES / secrets.token_hex(8)
    path.mkdir(mode=0o700)
    return path


def sandbox(image, arguments, *, directory=DEFINITIONS):
    scanner = Path(__file__).resolve().parent.parent
    properties = [
        "DynamicUser=yes", "PrivateNetwork=yes", "PrivateDevices=yes", "NoNewPrivileges=yes",
        "ProtectSystem=strict", "ProtectHome=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
        "ProtectControlGroups=yes", "RestrictAddressFamilies=AF_UNIX", "RestrictNamespaces=yes",
        "RestrictSUIDSGID=yes", "LockPersonality=yes", "CapabilityBoundingSet=", "TasksMax=24",
        "MemoryMax=1450M", "RuntimeMaxSec=27min", "UMask=0077",
        "TemporaryFileSystem=/run:ro /var:ro /etc:ro /tmp:mode=1777,size=320M,noexec,nodev,nosuid",
        "BindReadOnlyPaths={}:/mnt/source.img {}:/mnt/definitions {}:/mnt/clamav {}:/mnt/checker".format(
            image, directory, CLAM, scanner),
    ]
    args = ["systemd-run", "--quiet", "--pipe", "--wait", "--collect", "--setenv=LC_ALL=C"]
    args.extend("--property=" + prop for prop in properties)
    args.extend(["/usr/bin/python3", "-I", "-c",
                 "import runpy,sys;sys.path.insert(0,'/mnt/checker');"
                 "runpy.run_module('usb_checker.scanner',run_name='__main__')"])
    return command([*args, *arguments], timeout=1650)


def sandbox_probe():
    result = sandbox(Path(__file__).resolve(), ["probe"])
    details = json.loads(result.stdout)
    if details.get("sandbox") != "ok":
        raise CheckError("The sandbox preflight did not return its success marker.")
    return details


def scan_image(path, image, sector):
    status(path, phase="analyzing", message="Inspecting partition layout and scanning files in the sandbox.")
    before = digest_image(image)
    try:
        result = sandbox(image, [str(sector), str(image.stat().st_size)])
        analysis = json.loads(result.stdout)
        if not isinstance(analysis, dict) or not isinstance(analysis.get("limitations"), list):
            raise ValueError("Invalid scanner response")
    except (CheckError, OSError, ValueError, subprocess.SubprocessError) as error:
        analysis = {"limitations": ["Analysis sandbox failed: {}".format(safe_label(str(error)))],
                    "findings": [], "partitions": [], "unallocated": [], "selected_files": 0}
    expected = status(path).get("image_sha256")
    if before != expected or digest_image(image) != expected:
        raise CheckError("The image hash changed after capture.")
    analysis.update({
        "schema_version": 1, "case": path.name, "image_sha256": expected,
        "size_bytes": image.stat().st_size, "sector_bytes": sector,
        "usb": status(path).get("usb"),
        "scope": "Partition layout, gap samples and selected filesystem files",
    })
    return write_report(path, analysis)


def write_report(path, analysis, *, verdict=None):
    findings = analysis.get("findings", [])
    limitations = analysis.get("limitations", [])
    malicious = analysis.get("finding_counts", {}).get("malicious", 0)
    if verdict is None:
        verdict = "nothing-found"
        if malicious or any(finding["severity"] == "malicious" for finding in findings):
            verdict = "malicious"
        elif findings or limitations:
            verdict = "review"
    coverage = "partial" if limitations else "complete"
    analysis.update(verdict=verdict, coverage=coverage)
    write_json(path / "report.json", analysis)
    lines = [
        "USB Checker report", "", "Case {}".format(path.name), "Verdict {}".format(verdict),
        "Coverage {}".format(coverage), "SHA-256 {}".format(analysis.get("image_sha256") or "unavailable"),
        "Scope {}".format(analysis.get("scope", "USB device class inspection")),
        "", "Findings ({})".format(len(findings)),
    ]
    lines.extend("- " + json.dumps(finding, ensure_ascii=True, sort_keys=True) for finding in findings)
    if analysis.get("omitted_findings"):
        lines.append("Additional findings omitted from detail: {}".format(analysis["omitted_findings"]))
    lines.extend(["", "Limitations ({})".format(len(limitations))])
    lines.extend("- " + safe_label(item) for item in limitations)
    (path / "report.txt").write_text("\n".join(lines) + "\n")
    return {"case": path.name, "verdict": verdict, "coverage": coverage,
            "image_sha256": analysis.get("image_sha256"), "report": str(path / "report.json")}


def image_copy(path, fd, size, monitor=lambda: None, verify_source=lambda: None):
    if shutil.disk_usage(path).free < size + MIN_FREE:
        raise CheckError("Insufficient space for the image while retaining 384 MiB of free space.")
    written = 0
    last_update = 0
    digest = hashlib.sha256()
    partial = path / "image.partial"
    with partial.open("xb") as output:
        while written < size:
            monitor()
            chunk = os.read(fd, min(1024 * 1024, size - written))
            if not chunk:
                raise CheckError("The source ended before its advertised size.")
            output.write(chunk)
            digest.update(chunk)
            written += len(chunk)
            now = time.monotonic()
            if now - last_update >= 2:
                status(path, phase="imaging", bytes_read=written, size_bytes=size,
                       message="Creating a read-only evidence image.")
                last_update = now
        monitor()
        verify_source()
        output.flush()
        os.fsync(output.fileno())
    expected = digest.hexdigest()
    status(path, phase="verifying", bytes_read=written, size_bytes=size, message="Re-reading the image to verify SHA-256.")
    if digest_image(partial) != expected:
        raise CheckError("The evidence image failed SHA-256 verification.")
    monitor()
    os.chmod(partial, 0o444)
    image = path / "image.raw"
    partial.rename(image)
    status(path, image_sha256=expected, size_bytes=written)
    return image


def capture(path, wait_seconds):
    with lock(wait=True):
        sandbox_probe()
        state = usb.prepare_gate(path.name)
        status(path, phase="armed", message="USB gate is armed. Plug in one device directly. Keep the host powered on.")
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            arrived = usb.new_devices(state)
            if arrived:
                break
            time.sleep(0.25)
        else:
            status(path, phase="held", message="Insertion timeout. Confirm suspect media is physically removed to restore USB.")
            return
        try:
            if len(arrived) != 1:
                raise CheckError("More than one new USB device was detected.")
            name, identity = next(iter(arrived.items()))
            descriptor = usb.USB / "devices" / name / "descriptors"
            raw = descriptor.read_bytes()
            details = {"sha256": hashlib.sha256(raw).hexdigest()}
            status(path, usb=details)
            details, suffix = usb.parse_descriptors(raw)
            status(path, usb=details)
            if suffix is None:
                raise CheckError("The device is outside the supported single-interface USB mass-storage class.")
            interface = usb.authorize_storage(state, name, identity, suffix, details["sha256"])
        except (CheckError, OSError) as error:
            report = write_report(path, {
                "schema_version": 1, "case": path.name, "usb": status(path).get("usb"),
                "findings": [], "limitations": [str(error)],
            }, verdict="refused")
            status(path, phase="remove", result=report,
                   message="USB refused. Physically unplug it and confirm removal.")
            image = None
        else:
            def monitor():
                if usb.new_devices(state) != {name: identity}:
                    raise CheckError("USB identity changed during imaging. The image is incomplete.")
                if len(list(interface.glob("host*/target*/*:*:*:*"))) > 1:
                    raise CheckError("Multiple storage LUNs are refused.")

            fd, size, sector, disk = usb.open_disk(state, interface, monitor)
            try:
                status(path, device=disk, sector_bytes=sector, kernel_read_only=True)
                image = image_copy(path, fd, size, monitor)
            finally:
                os.close(fd)
            usb.deauthorize(state)
            status(path, phase="remove", message="Image verified. Physically unplug the device and confirm removal.")

        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if (path / "removed").exists():
                if usb.restore_gate(state, confirmed=True):
                    status(path, removal_confirmed=True)
                    break
                (path / "removed").unlink()
                status(path, phase="remove", message="A new USB device is still present. Unplug it and confirm again.")
            time.sleep(0.25)
        else:
            status(path, phase="held", message="USB remains held. Physically unplug the device before confirming removal.")
            return

        if image is None:
            status(path, phase="refused", message="Unsupported or unsafe USB classes. Device refused.")
        else:
            result = scan_image(path, image, sector)
            status(path, phase="done", result=result, message="Report ready.")


def start(wait_seconds):
    with lock():
        if usb.JOURNAL.exists():
            raise CheckError("Restore the held gate before creating a new USB case.")
        current = STATE / "active"
        if current.exists():
            existing = current.read_text().strip()
            response = command(["systemctl", "is-active", "usb-check-{}.service".format(existing)], check=False)
            if response.returncode == 0:
                raise CheckError("A USB Checker job is running.")
        path = new_case()
        status(path, phase="starting", message="Checking sandbox and USB gate prerequisites.")
        current.write_text(path.name)
        try:
            command([
                "systemd-run", "--quiet", "--collect", "--unit=usb-check-" + path.name,
                "--property=Type=exec", "--property=RuntimeMaxSec=6h", "--property=UMask=0077",
                "--property=ExecStopPost={} _stopped {}".format(CLI, path.name),
                CLI, "_capture", path.name, str(wait_seconds),
            ], timeout=30)
        except BaseException:
            current.unlink(missing_ok=True)
            raise
    return status(path)


def stopped(path):
    with lock(wait=True):
        if not usb.JOURNAL.exists():
            if status(path)["phase"] not in FINAL_PHASES:
                status(path, phase="failed", message="USB Checker stopped before completing the case.")
            return
        gate = read_json(usb.JOURNAL)
        if gate["case"] != path.name:
            return
        try:
            restored = usb.restore_gate(gate)
        except (CheckError, OSError, subprocess.SubprocessError):
            restored = False
        if not restored:
            current = status(path)
            previous = current.get("message", "The job stopped.")
            status(path, phase="held", message=previous + " Confirm physical removal to restore USB.")
        elif status(path)["phase"] not in FINAL_PHASES:
            status(path, phase="failed", message="USB Checker stopped before capture started.")


def removed(path):
    current = status(path)
    if current["phase"] not in ("held", "remove"):
        if current.get("removal_confirmed"):
            return current
        raise CheckError("Removal can be confirmed after imaging, refusal or a held gate.")
    if current["phase"] == "held":
        with lock(wait=True):
            current = status(path)
            if current.get("removal_confirmed"):
                return current
            if current["phase"] != "held":
                raise CheckError("The gate state changed. Refresh case status.")
            gate = read_json(usb.JOURNAL)
            if gate["case"] != path.name:
                raise CheckError("A different case holds the USB gate.")
            restored = usb.restore_gate(gate, confirmed=True)
            if not restored:
                raise CheckError("A new USB device appeared before restore.")
            previous = current.get("result")
            status(path, phase="refused" if previous else "failed", removal_confirmed=True,
                   message="USB gate restored.")
    else:
        # The capture worker owns the gate lock. A marker is scoped to this case
        # and the worker verifies both the gate and device absence before restore.
        (path / "removed").touch(mode=0o600)
    return status(path)


def guided(wait_seconds):
    if not sys.stdin.isatty():
        raise CheckError("Use a terminal for the guided check, or run start and poll status.")
    current = start(wait_seconds)
    path = case_path(current["case"])
    print("USB Checker case {}".format(path.name), flush=True)
    sequence = None
    try:
        while True:
            current = status(path)
            phase = current["phase"]
            signature = (phase, current.get("message"), current.get("bytes_read"))
            if signature != sequence:
                sequence = signature
                print(current["message"], flush=True)
                if phase == "imaging":
                    print("{:,} of {:,} bytes".format(current["bytes_read"], current["size_bytes"]), flush=True)
                if phase in ("remove", "held"):
                    if current.get("image_sha256"):
                        print("SHA-256 {}".format(current["image_sha256"]), flush=True)
                    if not sys.stdin.isatty():
                        return current
                    answer = input('Type "removed" after physically unplugging the device, or press Enter to leave USB held: ')
                    if answer.strip() != "removed":
                        return current
                    try:
                        current = removed(path)
                    except CheckError as error:
                        print(error, flush=True)
                        sequence = None
                    if phase == "held" and current["phase"] != "held":
                        return current
            if phase in FINAL_PHASES and phase != "held":
                return current
            time.sleep(0.3)
    except (KeyboardInterrupt, EOFError):
        raise CheckError("The job continues on the host. Recover with usb-check status {}.".format(path.name))


def analyze(source, sector):
    with lock():
        pinned = os.open(source, os.O_PATH | os.O_NOFOLLOW)
        try:
            initial = os.fstat(pinned)
            if not stat.S_ISREG(initial.st_mode) or initial.st_size <= 0 or initial.st_size % sector:
                raise CheckError("Analyze requires a regular image file aligned to the sector size.")
            fd = os.open("/proc/self/fd/{}".format(pinned), os.O_RDONLY | os.O_NONBLOCK)
            try:
                path = new_case()

                def unchanged():
                    final = os.fstat(fd)
                    if (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (
                            final.st_size, final.st_mtime_ns, final.st_ctime_ns):
                        raise CheckError("The source image changed during capture.")

                image = image_copy(path, fd, initial.st_size, verify_source=unchanged)
            finally:
                os.close(fd)
        finally:
            os.close(pinned)
        result = scan_image(path, image, sector)
        status(path, phase="done", result=result, message="Report ready.")
        return result


def clam_tool(name, args):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LD_LIBRARY_PATH": str(CLAM / "lib")}
    result = subprocess.run([*clam_args(CLAM, name), *args], env=env, text=True, capture_output=True, timeout=480)
    return result.returncode, result.stdout, result.stderr


def update_signatures():
    with lock():
        if usb.JOURNAL.exists():
            raise CheckError("Restore the USB gate before updating signatures.")
        last_update = DATA / "last-definition-attempt"
        if last_update.is_file() and time.time() - last_update.stat().st_mtime < 3600:
            expose_definitions()
            return {"definitions": definition_status(), "message": "Signature updates run at most once per hour."}
        last_update.touch(mode=0o600)
        config = DATA / "freshclam.conf"
        config.write_text("DatabaseDirectory {}\nDatabaseOwner usb-checker-db\n"
                          "DatabaseMirror database.clamav.net\nMaxAttempts 1\n".format(DEFINITIONS))
        try:
            code, output, error = clam_tool("freshclam", ["--config-file", str(config)])
        finally:
            expose_definitions()
        if code:
            raise CheckError("Definition update failed. {}".format(safe_label(error or output)))
        return {"definitions": definition_status()}


def expose_definitions():
    for name in ("main", "daily", "bytecode"):
        for extension in ("cvd", "cld"):
            path = DEFINITIONS / "{}.{}".format(name, extension)
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                continue
            try:
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    # Signatures are public. The unprivileged sandbox bind has no write access.
                    os.fchmod(fd, 0o644)
            finally:
                os.close(fd)


def definition_status():
    return signature_status(DEFINITIONS, lambda args: clam_tool("sigtool", args))


def doctor():
    for program in ("mmls", "fls", "icat", "systemd-run", "udevadm"):
        if shutil.which(program) is None:
            raise CheckError("Required tool {} is missing.".format(program))
    code, version, _ = clam_tool("clamscan", ["--version"])
    if code:
        raise CheckError("ClamAV is unavailable.")
    return {"version": __version__, "scanner": version.strip(), **sandbox_probe(),
            "gate_held": usb.JOURNAL.exists()}


def main():
    os.umask(0o077)
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin"
    parser = argparse.ArgumentParser(prog="usb-check", description="Read-only USB capture and malware triage.")
    subs = parser.add_subparsers(dest="action", required=True)
    for action in ("version", "doctor", "gate-status", "update-signatures"):
        subs.add_parser(action)
    for action in ("check", "start"):
        sub = subs.add_parser(action)
        sub.add_argument("--wait", type=int, choices=range(5, 601), metavar="SECONDS", default=600)
    for action in ("status", "removed", "report", "_stopped", "_capture"):
        sub = subs.add_parser(action)
        sub.add_argument("case")
        if action == "_capture":
            sub.add_argument("wait", type=int)
    sub = subs.add_parser("analyze")
    sub.add_argument("image", type=Path)
    sub.add_argument("--sector-size", type=int, choices=[512, 1024, 2048, 4096], default=512)
    options = parser.parse_args()
    actions = {
        "version": lambda: {"version": __version__},
        "doctor": doctor, "gate-status": lambda: read_json(usb.JOURNAL) if usb.JOURNAL.exists() else {"armed": False},
        "update-signatures": update_signatures, "start": lambda: start(options.wait),
        "check": lambda: guided(options.wait), "analyze": lambda: analyze(options.image, options.sector_size),
        "status": lambda: status(case_path(options.case)), "removed": lambda: removed(case_path(options.case)),
        "report": lambda: read_json(case_path(options.case) / "report.json"),
        "_capture": lambda: capture(case_path(options.case), options.wait),
        "_stopped": lambda: stopped(case_path(options.case)),
    }
    try:
        if options.action != "version" and os.getuid():
            raise CheckError("Run usb-check with sudo on the triage host.")
        result = actions[options.action]()
        if result is not None:
            print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    except (CheckError, OSError, ValueError, subprocess.SubprocessError) as error:
        if options.action == "_capture":
            phase = "held" if usb.JOURNAL.exists() else "failed"
            status(case_path(options.case), phase=phase, message=str(error))
        print(json.dumps({"error": str(error)}, ensure_ascii=True), file=sys.stderr)
        sys.exit(1)
