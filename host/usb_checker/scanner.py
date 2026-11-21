import hashlib
import json
import os
import re
import resource
import subprocess
import tempfile
from email.utils import parsedate_to_datetime
from pathlib import Path
from time import time

from .common import CheckError, clam_args

SOURCE = "/mnt/source.img"
DEFS = Path("/mnt/definitions")
CLAM = Path("/mnt/clamav")
STAGE_LIMIT = 256 * 1024 * 1024
FILE_LIMIT = 32 * 1024 * 1024
FILE_COUNT = 1000
REPORT_FINDINGS = 1000
OUTPUT_LIMIT = 4 * 1024 * 1024
EXECUTABLE = re.compile(r"\.(exe|com|scr|bat|cmd|ps1|vbs|js|lnk|msi|elf|sh)$", re.I)
DOUBLE = re.compile(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.", re.I)
ENTRY = re.compile(r"^([^\s]+)\s+(\*\s+)?([0-9]+(?:-[0-9]+){0,2}):\s?(.*)$")
TABLE_ENTRY = re.compile(r"^\s*[0-9]+:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$")


def subprocess_file_limit(limit):
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def tool(args, *, size=OUTPUT_LIMIT, timeout=60, destination=None, temporary_file_limit=None):
    environment = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                   "LD_LIBRARY_PATH": "/mnt/clamav/lib", "TMPDIR": "/tmp"}
    with tempfile.TemporaryFile(dir="/tmp") as stderr:
        output = tempfile.TemporaryFile(dir="/tmp") if destination is None else destination.open("xb")
        with output:
            try:
                result = subprocess.run(args, env=environment, stdout=output, stderr=stderr,
                                        timeout=timeout,
                                        preexec_fn=lambda: subprocess_file_limit(temporary_file_limit or size))
                returncode = result.returncode
            except subprocess.TimeoutExpired:
                returncode = 124
            stderr.seek(0)
            message = stderr.read(4096).decode("utf-8", "replace").strip()
            output.seek(0)
            content = "" if destination is not None else output.read(size).decode("utf-8", "replace")
            return returncode, content, message


def safe_label(value):
    # Names are data and remain printable single-line strings in both reports.
    return "".join(character if character.isprintable() else "\\u{:04x}".format(ord(character))
                   for character in value)[:400]


def signature_status(database, sigtool):
    official = {}
    for name in ("main", "daily", "bytecode"):
        for extension in ("cld", "cvd"):
            path = database / "{}.{}".format(name, extension)
            if path.is_file():
                official[name] = path
                break
    if set(official) != {"main", "daily", "bytecode"}:
        return {"state": "missing", "databases": sorted(official)}
    rc, output, _ = sigtool(["--info", str(official["daily"])])
    result = {"state": "unverified", "databases": sorted(official)}
    if rc:
        return result
    for line in output.splitlines():
        if line.startswith("Version:"):
            result["daily_version"] = line.split(":", 1)[1].strip()
        elif line.startswith("Build time:"):
            stamp = line.split(":", 1)[1].strip()
            try:
                # ClamAV prints "DD Mon YYYY HH-MM ±ZZZZ" for a CVD header.
                timestamp = parsedate_to_datetime(stamp.replace("-", ":", 1) if re.search(
                    r"\d\d-\d\d [+-]\d{4}$", stamp) else stamp).timestamp()
            except (ValueError, TypeError, OSError, OverflowError):
                return result
            age = (time() - timestamp) / 86400
            result["daily_age_days"] = round(age, 2)
            result["state"] = "unverified" if age < -1 else "fresh" if age <= 2 else "stale"
    return result


def layout(sector, image_size, issues, findings):
    code, output, detail = tool(["/usr/bin/mmls", "-i", "raw", "-b", str(sector), SOURCE])
    partitions = []
    unallocated = []
    metadata = []
    if code != 0:
        if code != 1 or (detail and "Cannot determine partition type" not in detail):
            issues.append("Partition table inspection returned an error.")
        return partitions, unallocated
    for line in output.splitlines():
        entry = TABLE_ENTRY.fullmatch(line)
        if not entry:
            continue
        slot, start, end, length, description = entry.groups()
        start, end, length = int(start), int(end), int(length)
        if end < start or end - start + 1 != length or (end + 1) * sector > image_size:
            issues.append("Partition layout contains an out-of-bounds range.")
            continue
        area = {"start_sector": start, "sectors": length, "description": safe_label(description)}
        if slot == "Meta":
            metadata.append((start, end + 1))
        elif slot == "-------":
            unallocated.append(area)
        else:
            partitions.append(area)
    partitions.sort(key=lambda entry: entry["start_sector"])
    for left, right in zip(partitions, partitions[1:]):
        if left["start_sector"] + left["sectors"] > right["start_sector"]:
            findings.append({"kind": "overlapping partitions", "severity": "review"})
            issues.append("Overlapping partition boundaries limit filesystem interpretation.")
    # Small bounded samples surface nonzero data in gaps without claiming a full carve.
    with open(SOURCE, "rb") as image:
        for gap in unallocated[:256]:
            start = gap["start_sector"]
            end = start + gap["sectors"]
            for metadata_start, metadata_end in sorted(metadata):
                if metadata_start <= start < metadata_end:
                    start = metadata_end
                elif metadata_start > start:
                    end = min(end, metadata_start)
                    break
            if start >= end:
                continue
            image.seek(start * sector)
            sample = image.read(min(4096, (end - start) * sector))
            if any(sample):
                findings.append({"kind": "data at start of unallocated range", "severity": "review",
                                 "sector": start})
    if len(unallocated) > 256:
        issues.append("Only the first 256 unallocated ranges were sampled.")
    return partitions, unallocated


def file_review(name, address, offset, deleted):
    reasons = []
    leaf = name.rsplit("/", 1)[-1]
    if leaf.casefold() == "autorun.inf":
        reasons.append("autorun file")
    if DOUBLE.search(leaf) and EXECUTABLE.search(leaf):
        reasons.append("document-like executable name")
    if any(character in name for character in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069"):
        reasons.append("bidirectional filename control")
    if ":" in leaf and address.endswith("-128-0") is False and "-128-" in address:
        reasons.append("NTFS alternate data stream")
    return [{"kind": reason, "severity": "review", "file": safe_label(name),
             "sector": offset, "deleted": deleted} for reason in reasons]


def collect_files(sector, partitions, issues, findings, samples):
    total = 0
    for offset in [item["start_sector"] for item in partitions] or [0]:
        arguments = ["-i", "raw", "-b", str(sector), "-o", str(offset)]
        rc, listing, _ = tool(["/usr/bin/fls", "-F", "-r", "-p", *arguments, SOURCE], timeout=180)
        if rc:
            issues.append("Filesystem at sector {} is unsupported or unreadable.".format(offset))
            continue
        for line in listing.split("\n"):
            entry = ENTRY.fullmatch(line)
            if entry is None:
                if line.strip():
                    issues.append("A filesystem entry could not be decoded.")
                continue
            kind, deleted, address, name = entry.groups()
            if not kind.startswith("r/") or name.startswith("$OrphanFiles/"):
                continue
            if len(samples) >= FILE_COUNT or total >= STAGE_LIMIT:
                issues.append("The file count or total scan budget was reached.")
                return
            findings.extend(file_review(name, address, offset, bool(deleted)))
            sample = Path("/tmp/scan/{:06d}.bin".format(len(samples)))
            args = ["/usr/bin/icat", *arguments]
            if deleted:
                args.append("-r")
            if total >= STAGE_LIMIT:
                break
            cap = min(FILE_LIMIT, STAGE_LIMIT - total)
            rc, _, _ = tool([*args, SOURCE, address], size=cap + 1, destination=sample, timeout=45)
            length = sample.stat().st_size
            if rc or length > cap:
                sample.unlink()
                issues.append("Files beyond the size or recovery limits were skipped.")
                continue
            total += length
            samples[sample.name] = {"file": safe_label(name), "sector": offset, "deleted": bool(deleted)}


def scan(sector, image_size):
    issues, findings = [], []
    partitions, unallocated = layout(sector, image_size, issues, findings)
    Path("/tmp/scan").mkdir()
    samples = {}
    collect_files(sector, partitions, issues, findings, samples)
    definitions = signature_status(DEFS, lambda args: tool([*clam_args(CLAM, "sigtool"), *args]))
    if definitions["state"] != "fresh":
        issues.append("ClamAV definitions are {}.".format(definitions["state"]))
    if definitions["state"] != "missing" and samples:
        args = [*clam_args(CLAM, "clamscan"), "--database=/mnt/definitions", "--recursive=yes", "--infected", "--no-summary",
                "--max-filesize=32M", "--max-scansize=96M", "--max-recursion=12",
                "--alert-exceeds-max=yes", "--alert-encrypted=yes", "/tmp/scan"]
        rc, output, err = tool(args, timeout=900, temporary_file_limit=128 * 1024 * 1024)
        for line in output.split("\n"):
            matched = re.fullmatch(r"/tmp/scan/([0-9]+\.bin): (.{1,300}) FOUND", line)
            if matched and matched.group(1) in samples:
                signature = safe_label(matched.group(2))
                heuristic = signature.startswith("Heuristics.")
                findings.append({"kind": "ClamAV signature", "severity": "review" if heuristic else "malicious",
                                 "signature": signature, **samples[matched.group(1)]})
                if heuristic and ("Limits.Exceeded" in signature or "Encrypted" in signature):
                    issues.append("ClamAV reached an archive limit or encrypted content.")
        if rc not in (0, 1) or err or rc == 1 and not any(item["kind"] == "ClamAV signature" for item in findings):
            message = "ClamAV could not finish every selected file (exit {}).".format(rc)
            if err:
                message += " " + safe_label(err)
            issues.append(message)
    return {"partitions": partitions, "unallocated": unallocated, **summarize_findings(findings),
            "limitations": sorted(set(issues)), "definitions": definitions, "selected_files": len(samples)}


def summarize_findings(findings):
    malicious = sum(item["severity"] == "malicious" for item in findings)
    return {"findings": sorted(findings, key=lambda item: item["severity"] != "malicious")[:REPORT_FINDINGS],
            "finding_counts": {"malicious": malicious, "review": len(findings) - malicious},
            "omitted_findings": max(0, len(findings) - REPORT_FINDINGS)}


def digest_image(path):
    digest = hashlib.sha256()
    with path.open("rb") as image:
        for chunk in iter(lambda: image.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sandbox_main():
    import socket
    import sys

    if os.getuid() == 0 or Path("/dev/sda").exists():
        raise CheckError("The analysis sandbox is missing user or device isolation.")
    for address in (socket.AF_INET, socket.AF_INET6):
        try:
            sock = socket.socket(address)
        except OSError:
            continue
        sock.close()
        raise CheckError("The analysis sandbox allows IP sockets.")
    if len(sys.argv) == 2 and sys.argv[1] == "probe":
        try:
            with open(SOURCE, "r+b"):
                raise CheckError("The sandbox can write the source image.")
        except PermissionError:
            pass
        except OSError as error:
            if error.errno != 30:
                raise
        definitions = signature_status(DEFS, lambda args: tool([*clam_args(CLAM, "sigtool"), *args]))
        print(json.dumps({"sandbox": "ok", "definitions": definitions}))
    else:
        print(json.dumps(scan(int(sys.argv[1]), int(sys.argv[2])), ensure_ascii=True))


if __name__ == "__main__":
    sandbox_main()
