import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

STATE = Path("/run/usb-checker")
DATA = Path("/var/lib/usb-checker")
CASES = DATA / "cases"
DEFINITIONS = DATA / "definitions"
INSTALL = Path("/opt/usb-checker")
CLAM = INSTALL / "clamav" / "1.4.7" / "usr/local"
CLI = "/usr/local/bin/usb-check"
CASE_PATTERN = re.compile(r"[0-9a-f]{16}")


class CheckError(Exception):
    """A failed or unsafe operation with an operator-facing diagnostic."""


def command(args, *, check=True, **kwargs):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    result = subprocess.run(args, env=env, text=True, capture_output=True, **kwargs)
    if check and result.returncode:
        raise CheckError("{} failed: {}".format(Path(args[0]).name, result.stderr.strip()[:400]))
    return result


def clam_args(root, name):
    executable = str(root / "bin" / name)
    runtime = root / "compat"
    if not runtime.is_dir():
        return [executable]
    loaders = list(runtime.glob("ld-linux-*.so.*"))
    if len(loaders) != 1:
        raise CheckError("The isolated ClamAV runtime is incomplete.")
    return [str(loaders[0]), "--library-path", "{}:{}".format(root / "lib", runtime), executable]


def write_json(path, value, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            os.fchmod(output.fileno(), mode)
            json.dump(value, output, indent=2, ensure_ascii=True, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    return json.loads(path.read_text())


def case_path(case):
    if not CASE_PATTERN.fullmatch(case):
        raise CheckError("Invalid case ID.")
    path = CASES / case
    if not path.is_dir():
        raise CheckError("Case not found.")
    return path
