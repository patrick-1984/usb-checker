import argparse
import fcntl
import hashlib
import json
import os
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from . import __version__, usb
from .common import (
    CASES, CLAM, DATA, DEFINITIONS, STATE, CheckError, case_path,
    clam_args, command, read_json, write_json,
)
from .scanner import safe_label, signature_status

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


def sandbox(source, arguments, *, directory=DEFINITIONS, device=None, unit=None, monitor=None):
    scanner = Path(__file__).resolve().parent.parent
    properties = [
        "DynamicUser=yes", "PrivateNetwork=yes", "PrivateDevices=yes", "NoNewPrivileges=yes",
        "ProtectSystem=strict", "ProtectHome=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
        "ProtectControlGroups=yes", "RestrictAddressFamilies=AF_UNIX", "RestrictNamespaces=yes",
        "RestrictSUIDSGID=yes", "LockPersonality=yes", "CapabilityBoundingSet=", "TasksMax=24",
        "MemoryMax=1450M", "RuntimeMaxSec=27min", "UMask=0077",
        "TemporaryFileSystem=/run:ro /var:ro /etc:ro /tmp:mode=1777,size=320M,noexec,nodev,nosuid",
        "BindReadOnlyPaths={}:/mnt/usb-source {}:/mnt/definitions {}:/mnt/clamav {}:/mnt/checker".format(
            source, directory, CLAM, scanner),
    ]
    args = ["systemd-run", "--quiet", "--pipe", "--wait", "--collect", "--setenv=LC_ALL=C"]
    if device:
        properties.extend(["DeviceAllow={} r".format(device), "SupplementaryGroups=disk"])
        args.append("--unit=" + unit)
    args.extend("--property=" + prop for prop in properties)
    args.extend(["/usr/bin/python3", "-I", "-c",
                 "import runpy,sys;sys.path.insert(0,'/mnt/checker');"
                 "runpy.run_module('usb_checker.scanner',run_name='__main__')"])
    args.extend(arguments)
    if monitor is None:
        return command(args, timeout=1650)
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    with subprocess.Popen(args, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            while True:
                monitor()
                try:
                    output, error = process.communicate(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    continue
        except BaseException:
            command(["systemctl", "stop", unit + ".service"], check=False, timeout=25)
            process.kill()
            process.communicate()
            raise
    if process.returncode:
        raise CheckError("Read-only analysis sandbox failed: {}".format(safe_label(error)))
    return subprocess.CompletedProcess(args, 0, output, error)


def sandbox_probe():
    result = sandbox(Path(__file__).resolve(), ["probe"])
    details = json.loads(result.stdout)
    if details.get("sandbox") != "ok":
        raise CheckError("The sandbox preflight did not return its success marker.")
    return details


def scan_device(path, fd, disk, size, sector, monitor):
    status(path, phase="analyzing", message="Inspecting the read-only USB device directly. Keep it connected until the result is ready.")
    number = os.fstat(fd).st_rdev
    identity = "{}:{}".format(os.major(number), os.minor(number))
    source = "/proc/{}/fd/{}".format(os.getpid(), fd)
    try:
        result = sandbox(source, [str(sector), str(size), identity], device="/dev/" + disk,
                         unit="usb-check-scan-" + path.name, monitor=monitor)
        analysis = json.loads(result.stdout)
        if not isinstance(analysis, dict) or not isinstance(analysis.get("limitations"), list):
            raise ValueError("Invalid scanner response")
    except (CheckError, OSError, ValueError, subprocess.SubprocessError) as error:
        monitor()
        analysis = {"limitations": ["Analysis sandbox failed: {}".format(safe_label(str(error)))],
                    "findings": [], "partitions": [], "unallocated": [], "selected_files": 0}
    monitor()
    analysis.update({
        "schema_version": 1, "case": path.name, "kernel_read_only": True,
        "size_bytes": size, "sector_bytes": sector,
        "usb": status(path).get("usb"),
        "scope": "USB classes, read-only partition layout, gap samples and bounded filesystem malware triage",
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
        "Coverage {}".format(coverage),
        "Scope {}".format(analysis.get("scope", "USB device class inspection")),
        "", "Findings ({})".format(len(findings)),
    ]
    lines.extend("- " + json.dumps(finding, ensure_ascii=True, sort_keys=True) for finding in findings)
    if analysis.get("omitted_findings"):
        lines.append("Additional findings omitted from detail: {}".format(analysis["omitted_findings"]))
    lines.extend(["", "Limitations ({})".format(len(limitations))])
    lines.extend("- " + safe_label(item) for item in limitations)
    (path / "report.txt").write_text("\n".join(lines) + "\n")
    return {"case": path.name, "verdict": verdict, "coverage": coverage, "limitations": limitations,
            "report": str(path / "report.json")}


def resume_state(path):
    state = read_json(usb.JOURNAL)
    if state["case"] != path.name or not state["published"]:
        raise CheckError("This case cannot adopt a USB device while held.")
    devices = usb.new_devices(state)
    if len(devices) != 1:
        raise CheckError("Resume requires exactly one newly connected USB device.")
    name, identity = next(iter(devices.items()))
    if state.get("expected_device", [name, identity]) != [name, identity]:
        raise CheckError("The connected device does not match the authorized replacement identity.")
    if state["target"] is not None and state["target"] != {"name": name, "identity": identity}:
        raise CheckError("The connected device does not match the original held identity.")
    if not usb.PORT.fullmatch(name) or (usb.USB / "devices" / name / "authorized").read_text().strip() != "0":
        raise CheckError("Resume requires one unauthorized USB device on a direct port.")
    return state, [name, identity]


def capture(path, wait_seconds, *, resumed=False):
    with lock(wait=True):
        sandbox_probe()
        if resumed:
            state, device = resume_state(path)
            if status(path).get("resume_device") != device:
                raise CheckError("USB identity changed before the resumed case started.")
            arrived = {device[0]: device[1]}
        else:
            state = usb.prepare_gate(path.name)
            status(path, phase="armed", message="USB gate is armed. Plug in one device directly. Keep the host powered on.")
            deadline = time.monotonic() + wait_seconds
            while time.monotonic() < deadline:
                arrived = usb.new_devices(state)
                if arrived:
                    break
                time.sleep(0.25)
            else:
                status(path, phase="held", held_reason="insertion-timeout",
                       message="Insertion timeout. Resume with one attached device or confirm removal to restore USB.")
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
            refused = True
        else:
            def monitor():
                if usb.new_devices(state) != {name: identity}:
                    raise CheckError("USB identity changed during the direct check.")
                if len(list(interface.glob("host*/target*/*:*:*:*"))) > 1:
                    raise CheckError("Multiple storage LUNs are refused.")

            fd, size, sector, disk = usb.open_disk(state, interface, monitor)
            try:
                status(path, device=disk, size_bytes=size, sector_bytes=sector, kernel_read_only=True)
                report = scan_device(path, fd, disk, size, sector, monitor)
            finally:
                os.close(fd)
            usb.deauthorize(state)
            status(path, phase="remove", result=report,
                   message="Report ready. Physically unplug the device and confirm removal when ready.")
            refused = False

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

        if refused:
            status(path, phase="refused", message="Unsupported or unsafe USB classes. Device refused.")
        else:
            status(path, phase="done", result=report, message="Report ready.")


def launch_case(path, wait_seconds, *, resumed=False):
    executable = str(Path(sys.argv[0]).resolve())
    args = [
        "systemd-run", "--quiet", "--collect", "--unit=usb-check-" + path.name,
        "--property=Type=exec", "--property=RuntimeMaxSec=6h", "--property=UMask=0077",
        "--property=ExecStopPost={} _stopped {}".format(shlex.quote(executable), path.name),
        executable, "_capture", path.name, str(wait_seconds),
    ]
    if resumed:
        args.append("--resumed")
    command(args, timeout=30)


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
            launch_case(path, wait_seconds)
        except BaseException:
            current.unlink(missing_ok=True)
            raise
    return status(path)


def resume(path):
    with lock():
        previous = status(path)
        if previous["phase"] != "held" or previous.get("result"):
            raise CheckError("Only an incomplete held case can resume the USB check.")
        state, device = resume_state(path)
        state["expected_device"] = device
        write_json(usb.JOURNAL, state)
        current = {"case": path.name, "phase": "held", "resume_device": device,
                   "message": "Resuming the held USB check."}
        write_json(path / "status.json", current)
        try:
            launch_case(path, 0, resumed=True)
            status(path, phase="starting")
        except BaseException:
            write_json(path / "status.json", previous)
            raise
    return status(path)


def replacement_device(state):
    devices = usb.new_devices(state)
    old = state["target"]
    if len(devices) != 1 or not old:
        raise CheckError("A replacement check requires one new USB device and a previous device identity.")
    name, identity = next(iter(devices.items()))
    if {"name": name, "identity": identity} == old:
        raise CheckError("The previous USB device is still connected.")
    port = usb.USB / "devices" / name
    if not usb.PORT.fullmatch(name) or (port / "authorized").read_text().strip() != "0":
        raise CheckError("The replacement device must be unauthorized and on a direct port.")
    return [name, identity]


def next_case(previous):
    with lock():
        old_status = status(previous)
        state = read_json(usb.JOURNAL)
        if state["case"] != previous.name or old_status["phase"] != "held" or not old_status.get("result"):
            raise CheckError("The preceding completed case must still hold the USB gate.")
        device = replacement_device(state)
        path = new_case()
        status(path, phase="held", previous_case=previous.name, resume_device=device,
               message="Preparing a direct check under the existing USB gate.")
        old_active = (STATE / "active").read_text()
        next_state = {**state, "case": path.name, "target": None,
                      "held_rule_port": state["target"]["name"], "expected_device": device}
        try:
            write_json(usb.JOURNAL, next_state)
            (STATE / "active").write_text(path.name)
            launch_case(path, 0, resumed=True)
            status(path, phase="starting")
        except BaseException:
            write_json(usb.JOURNAL, state)
            (STATE / "active").write_text(old_active)
            status(path, phase="failed", message="The original USB gate remains held.")
            raise
        status(previous, successor=path.name)
    return status(path)


def stopped(path):
    with lock(wait=True):
        command(["systemctl", "stop", "usb-check-scan-{}.service".format(path.name)], check=False, timeout=25)
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
            if current["phase"] != "held":
                previous = current.get("message", "The job stopped.")
                status(path, phase="held", message=previous + " Confirm physical removal to restore USB.")
        elif status(path)["phase"] not in FINAL_PHASES:
            status(path, phase="failed", message="USB Checker stopped before capture started.")


def removed(path):
    current = status(path)
    if current["phase"] not in ("held", "remove"):
        if current.get("removal_confirmed"):
            return current
        raise CheckError("Removal can be confirmed after the check, refusal or a held gate.")
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
            result = current.get("result")
            phase = "refused" if result and result["verdict"] == "refused" else "done" if result else "failed"
            status(path, phase=phase, removal_confirmed=True, message="USB gate restored.")
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
    reported = False
    try:
        while True:
            current = status(path)
            phase = current["phase"]
            result = current.get("result")
            if result and not reported:
                print("Verdict {}. Coverage {}. Report {}".format(
                    result["verdict"], result["coverage"], result["report"]), flush=True)
                for limit in result.get("limitations", []):
                    print("- " + safe_label(limit), flush=True)
                reported = True
            signature = (phase, current.get("message"))
            if signature != sequence:
                sequence = signature
                print(current["message"], flush=True)
                if phase in ("remove", "held"):
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
    parser = argparse.ArgumentParser(prog="usb-check", description="Direct read-only USB safety and malware triage.")
    subs = parser.add_subparsers(dest="action", required=True)
    for action in ("version", "doctor", "gate-status", "update-signatures"):
        subs.add_parser(action)
    for action in ("check", "start"):
        sub = subs.add_parser(action)
        sub.add_argument("--wait", type=int, choices=range(5, 601), metavar="SECONDS", default=600)
    for action in ("status", "removed", "report", "resume", "next", "_stopped", "_capture"):
        sub = subs.add_parser(action)
        sub.add_argument("case")
        if action == "_capture":
            sub.add_argument("wait", type=int)
            sub.add_argument("--resumed", action="store_true")
    options = parser.parse_args()
    actions = {
        "version": lambda: {"version": __version__},
        "doctor": doctor, "gate-status": lambda: read_json(usb.JOURNAL) if usb.JOURNAL.exists() else {"armed": False},
        "update-signatures": update_signatures, "start": lambda: start(options.wait),
        "check": lambda: guided(options.wait),
        "status": lambda: status(case_path(options.case)), "removed": lambda: removed(case_path(options.case)),
        "resume": lambda: resume(case_path(options.case)),
        "next": lambda: next_case(case_path(options.case)),
        "report": lambda: read_json(case_path(options.case) / "report.json"),
        "_capture": lambda: capture(case_path(options.case), options.wait, resumed=options.resumed),
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
