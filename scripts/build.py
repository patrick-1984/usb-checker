#!/usr/bin/env python3
import base64
import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    version = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["version"]
    codex = json.loads((ROOT / ".codex-plugin/plugin.json").read_text())
    if codex["version"] != version:
        raise SystemExit("Plugin versions differ")
    versions = {
        "host/usb_checker/__init__.py": '__version__ = "{}"',
        "mcp/server.mjs": 'const version = "{}";',
        "host/install.sh": "version={}",
    }
    for relative, marker in versions.items():
        if marker.format(version) not in (ROOT / relative).read_text().splitlines():
            raise SystemExit("Version mismatch in " + relative)
    host = sorted((ROOT / "host/usb_checker").glob("*.py"))
    host += [ROOT / "host/cisco-talos.asc", ROOT / "host/usb-check"]
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as payload:
            for path in sorted(host):
                data = path.read_bytes()
                item = tarfile.TarInfo(str(path.relative_to(ROOT / "host")))
                item.size = len(data)
                item.mode = 0o755 if path.name == "usb-check" else 0o644
                payload.addfile(item, io.BytesIO(data))
    payload = buffer.getvalue()
    installer = (ROOT / "host/install.sh").read_bytes().replace(b"@PAYLOAD_SHA256@", sha(payload).encode())
    installer += b"\nexit 0\n__USB_CHECKER_PAYLOAD__\n" + base64.encodebytes(payload)
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    (output / "install.sh").write_bytes(installer)
    (output / "install.sh").chmod(0o755)
    archive = output / ("usb-checker-" + version + ".zip")
    files = host + [ROOT / name for name in [
        ".claude-plugin/plugin.json", ".codex-plugin/plugin.json", ".mcp.json",
        "host/install.sh", "mcp-codex.json", "mcp/server.mjs", "README.md",
        "skills/usb-check/SKILL.md",
    ]]
    hashes = {}
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for path in sorted(files):
            relative = str(path.relative_to(ROOT))
            data = path.read_bytes()
            hashes[relative] = sha(data)
            entry = zipfile.ZipInfo(relative, date_time=(2026, 1, 1, 0, 0, 0))
            entry.external_attr = (0o100755 if path.name in {"usb-check", "install.sh"} else 0o100644) << 16
            target.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED)
        entry = zipfile.ZipInfo("_build.json", date_time=(2026, 1, 1, 0, 0, 0))
        entry.external_attr = 0o100644 << 16
        target.writestr(entry, json.dumps({"version": version, "files": hashes}, sort_keys=True) + "\n")
    assets = [output / "install.sh", archive]
    (output / "SHA256SUMS").write_text("".join("{}  {}\n".format(sha(path.read_bytes()), path.name) for path in assets))


if __name__ == "__main__":
    main()
