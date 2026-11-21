#!/bin/sh
# This integration test creates and reads regular image files.
set -eu
umask 077
scratch=$(mktemp -d)
trap 'find "$scratch" -depth -delete' EXIT
control=${1:-signature}
case "$control" in signature|benign) ;; *) exit 2 ;; esac
python3 - "$scratch" "$control" <<'PY'
import struct
import sys
from pathlib import Path

root = Path(sys.argv[1])
files = root / "files"
files.mkdir()
(files / "readme.txt").write_text("USB Checker live test\n")
if sys.argv[2] == "signature":
    (files / "invoice.pdf.exe").write_text("Benign filename test\n")
    (files / "av-test.txt").write_bytes(
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}" + b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
with (root / "partition.raw").open("wb") as partition:
    partition.truncate(16 * 1024 * 1024)
with (root / "fixture.raw").open("wb") as image:
    image.seek(446)
    image.write(struct.pack("<B3sB3sII", 0, b"\0" * 3, 0x83, b"\0" * 3, 2048, 32768))
    image.seek(510)
    image.write(b"\x55\xaa")
    if sys.argv[2] == "signature":
        image.seek((2048 + 32768) * 512)
        image.write(b"gap sample")
    image.truncate(32 * 1024 * 1024)
PY
mkfs.ext2 -q -F -d "$scratch/files" "$scratch/partition.raw"
dd if="$scratch/partition.raw" of="$scratch/fixture.raw" bs=512 seek=2048 conv=notrunc status=none
/usr/local/bin/usb-check analyze "$scratch/fixture.raw" > "$scratch/result"
python3 - "$scratch" "$control" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
result = json.loads((root / "result").read_text())
report = json.loads(Path(result["report"]).read_text())
assert result["image_sha256"] == hashlib.sha256((root / "fixture.raw").read_bytes()).hexdigest(), report
assert any(part["start_sector"] == 2048 for part in report["partitions"]), report
if sys.argv[2] == "signature":
    assert any(item["kind"] == "data at start of unallocated range" for item in report["findings"]), report
    assert any(item["kind"] == "document-like executable name" for item in report["findings"]), report
    assert any(item["kind"] == "ClamAV signature" and "eicar" in item["signature"].casefold()
               for item in report["findings"]), report
    assert result["verdict"] == "malicious", report
else:
    assert report["selected_files"] >= 1, report
    assert result["verdict"] == "nothing-found", report
    assert result["coverage"] == "complete", report
assert report["definitions"]["state"] == "fresh", report
print(json.dumps(result, sort_keys=True))
PY
