import array
import fcntl
import hashlib
import os
import re
import stat
import time
from pathlib import Path

from .common import CheckError, STATE, command, read_json, write_json

USB = Path("/sys/bus/usb")
BLOCK = Path("/sys/class/block")
DEFAULT = Path("/sys/module/usbcore/parameters/authorized_default")
AUTOPROBE = USB / "drivers_autoprobe"
JOURNAL = STATE / "gate.json"
RULE = Path("/run/udev/rules.d/05-usb-checker.rules")
RUNTIME_MASK = Path("/run/systemd/system/udisks2.service")
PORT = re.compile(r"[1-9][0-9]*-[1-9][0-9]*")
HUB = re.compile(r"usb[0-9]+")
# Linux block ioctls. BLKGETSIZE64 encodes the native size_t.
BLKROSET = 0x125D
BLKROGET = 0x125E
BLKSSZGET = 0x1268
BLKGETSIZE64 = 0x80081272


def usb_snapshot():
    result = {}
    for path in sorted((USB / "devices").iterdir()):
        if not (path / "devnum").exists():
            continue
        try:
            result[path.name] = [
                (path / "devnum").read_text().strip(),
                path.stat().st_ino,
            ]
        except FileNotFoundError:
            continue
    return result


def check_policy():
    for candidate in ("autofs.service", "usbmount.service"):
        if command(["systemctl", "is-active", candidate], check=False).returncode == 0:
            raise CheckError("Stop {} before arming.".format(candidate))
    if Path("/usr/share/usbmount/usbmount").exists():
        raise CheckError("USB mount rules are installed. Use a dedicated triage host.")
    # udev must support suppression of the standard persistent-storage blkid probe.
    rules = Path("/lib/udev/rules.d/60-persistent-storage.rules")
    if "UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG" not in rules.read_text():
        raise CheckError("The host udev rules cannot suppress automatic filesystem probing.")


def _write(path, value):
    path.write_text(value + "\n")
    if path.read_text().strip() != value:
        raise CheckError("Kernel USB policy write did not take effect at {}.".format(path))


def _reload_rules():
    command(["udevadm", "control", "--reload-rules"], timeout=15)


def _rule_text(port=None):
    if port is None:
        return "# USB Checker holds new devices unauthorized before selection.\n"
    return (
        'ACTION=="add|change", SUBSYSTEM=="block", KERNELS=="{}", '
        'KERNEL!="sda", KERNEL!="sda[0-9]*", '
        'ENV{{UDISKS_IGNORE}}="1", ENV{{SYSTEMD_READY}}="0", '
        'ENV{{UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG}}="1", OPTIONS+="nowatch"\n'
    ).format(port)


def prepare_gate(case):
    if JOURNAL.exists():
        raise CheckError("A USB gate is still armed. See usb-check gate-status.")
    if RULE.exists() or RULE.is_symlink():
        raise CheckError("The USB Checker runtime rule already exists.")
    check_policy()
    # The module must already be present when USB autoprobe is disabled.
    if not (USB / "drivers/usb-storage/bind").exists():
        command(["modprobe", "usb-storage"], timeout=20)
    if not (USB / "drivers/usb-storage/bind").exists():
        raise CheckError("The usb-storage driver cannot be explicitly bound.")
    baseline = usb_snapshot()
    hubs = [name for name in baseline if HUB.fullmatch(name)]
    if not hubs:
        raise CheckError("No USB root hub found.")
    paths = [DEFAULT, AUTOPROBE]
    paths.extend(USB / "devices" / hub / attribute for hub in hubs
                 for attribute in ("authorized_default", "interface_authorized_default"))
    records = [{"path": str(path), "before": path.read_text().strip()} for path in paths]
    service = command(["systemctl", "show", "-p", "LoadState", "--value", "udisks2.service"]).stdout.strip()
    active = command(["systemctl", "is-active", "udisks2.service"], check=False).returncode == 0
    state = {
        "case": case,
        "baseline": baseline,
        "old_blocks": sorted(path.name for path in BLOCK.iterdir()),
        "settings": records,
        "service": service,
        "service_active": active,
        "mask_intended": service == "loaded",
        "published": False,
        "target": None,
    }
    write_json(JOURNAL, state)
    for entry in records:
        _write(Path(entry["path"]), "0")
    if state["mask_intended"]:
        if RUNTIME_MASK.exists() or RUNTIME_MASK.is_symlink():
            raise CheckError("A runtime UDisks override already exists.")
        command(["systemctl", "mask", "--runtime", "udisks2.service"], timeout=20)
    if active:
        command(["systemctl", "stop", "udisks2.service"], timeout=20)

    RULE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with RULE.open("x") as rule:
        rule.write(_rule_text())
    _reload_rules()
    if usb_snapshot() != baseline:
        raise CheckError("USB devices changed while arming. Remove any newly attached equipment.")
    assert_gate(state)
    state["published"] = True
    write_json(JOURNAL, state)
    return state


def assert_gate(state):
    for entry in state["settings"]:
        if Path(entry["path"]).read_text().strip() != "0":
            raise CheckError("USB authorization policy changed during the check.")
    if state["mask_intended"] and (
            not RUNTIME_MASK.is_symlink() or os.readlink(RUNTIME_MASK) != "/dev/null"):
        raise CheckError("The UDisks runtime mask changed during the check.")
    target = state["target"]
    if RULE.read_text() != _rule_text(target["name"] if target else None):
        raise CheckError("The USB Checker runtime rule changed during the check.")


def new_devices(state):
    assert_gate(state)
    snapshot = usb_snapshot()
    for name, identity in state["baseline"].items():
        if snapshot.get(name) != identity:
            raise CheckError("A baseline USB device or root hub changed during the check.")
    return {name: identity for name, identity in snapshot.items() if name not in state["baseline"]}


def parse_descriptors(raw):
    if len(raw) < 36 or raw[:2] != b"\x12\x01":
        raise CheckError("Incomplete USB device descriptors.")
    digest = hashlib.sha256(raw).hexdigest()
    interfaces = []
    details = {"sha256": digest, "device_class": list(raw[4:7]), "interfaces": interfaces}
    if len(raw) > 65553 or raw[17] != 1 or raw[18:20] != b"\x09\x02":
        return details, None
    if int.from_bytes(raw[20:22], "little") != len(raw) - 18:
        raise CheckError("USB configuration length does not match the descriptors.")
    endpoints = []
    supported_descriptors = True
    offset = 27
    while offset < len(raw):
        length, kind = raw[offset:offset + 2] if len(raw) - offset >= 2 else (0, 0)
        if length < 2 or offset + length > len(raw):
            raise CheckError("Malformed USB interface descriptor.")
        part = raw[offset:offset + length]
        if kind == 4 and length == 9:
            interfaces.append({
                "number": part[2], "alternate": part[3], "endpoints": part[4],
                "class": part[5], "subclass": part[6], "protocol": part[7],
            })
        elif kind == 5 and length == 7:
            endpoints.append((part[2], part[3]))
        elif kind != 48 or length != 6:
            supported_descriptors = False
        offset += length
    if len(interfaces) != 1 or not supported_descriptors or raw[4:7] != b"\x00\x00\x00" or raw[22] != 1 or not raw[23]:
        return details, None
    interface = interfaces[0]
    if [interface[key] for key in ("alternate", "endpoints", "class", "subclass", "protocol")] != [0, 2, 8, 6, 0x50]:
        return details, None
    if len(endpoints) != 2 or {address & 0xF0 for address, _ in endpoints} != {0, 0x80}:
        return details, None
    if any(not address & 0x0F or attributes != 2 for address, attributes in endpoints):
        return details, None
    return details, "{}.{}".format(raw[23], interface["number"])


def authorize_storage(state, name, identity, interface_suffix, digest):
    if not PORT.fullmatch(name):
        raise CheckError("Use a direct USB port. Hubs are refused.")
    if new_devices(state) != {name: identity}:
        raise CheckError("USB devices changed before storage authorization.")
    path = USB / "devices" / name
    if (path / "authorized").read_text().strip() != "0":
        raise CheckError("The new device was already authorized by the host.")
    state["target"] = {"name": name, "identity": identity}
    write_json(JOURNAL, state)
    RULE.write_text(_rule_text(name))
    _reload_rules()
    if new_devices(state) != {name: identity}:
        raise CheckError("USB devices changed before binding storage.")
    if hashlib.sha256((path / "descriptors").read_bytes()).hexdigest() != digest:
        raise CheckError("USB descriptors changed before authorization.")
    _write(path / "authorized", "1")
    interface = "{}:{}".format(name, interface_suffix)
    interface_path = USB / "devices" / interface
    matches = list((USB / "devices").glob("{}:*".format(name)))
    if matches != [interface_path] or (interface_path / "driver").exists():
        raise CheckError("USB configuration or driver binding changed.")
    observed = [int((interface_path / field).read_text(), 16) for field in
                ("bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol")]
    if observed != [8, 6, 0x50] or (interface_path / "authorized").read_text().strip() != "0":
        raise CheckError("The kernel interface is outside the approved storage class.")
    _write(interface_path / "authorized", "1")
    (USB / "drivers/usb-storage/bind").write_text(interface + "\n")
    if (interface_path / "driver").resolve(strict=True) != USB / "drivers/usb-storage":
        raise CheckError("The approved USB storage driver did not bind.")
    return interface_path.resolve(strict=True)


def _candidate_blocks(interface, old_blocks):
    return [
        path for path in BLOCK.iterdir()
        if path.name not in old_blocks
        and re.fullmatch(r"sd[a-z]+", path.name)
        and path.name != "sda"
        and interface in path.resolve().parents
        and not (path / "partition").exists()
    ]


def _verify_unused(block, identity):
    if block.name == "sda" or block.name.startswith("sda") and block.name[3:].isdigit():
        raise CheckError("The host system disk is explicitly excluded.")
    related = [block]
    related += [path for path in block.iterdir() if (path / "partition").is_file()]
    numbers = {(path / "dev").read_text().strip() for path in related}
    if identity not in numbers or any(list((path / "holders").iterdir()) for path in related):
        raise CheckError("Storage identity changed or a block holder already claimed it.")
    for mountinfo in (Path("/proc/self/mountinfo"), Path("/proc/1/mountinfo")):
        if any(line.split()[2] in numbers for line in mountinfo.read_text().splitlines()):
            raise CheckError("The newly attached disk is already mounted.")
    for line in Path("/proc/swaps").read_text().splitlines()[1:]:
        swap = Path(line.split()[0])
        try:
            number = swap.stat().st_rdev
        except FileNotFoundError:
            continue
        if "{}:{}".format(os.major(number), os.minor(number)) in numbers:
            raise CheckError("The newly attached disk is already used for swap.")


def open_disk(state, interface, monitor):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        monitor()
        if len(list(interface.glob("host*/target*/*:*:*:*"))) > 1:
            raise CheckError("Multiple storage LUNs are refused.")
        candidates = _candidate_blocks(interface, state["old_blocks"])
        if len(candidates) > 1:
            raise CheckError("Multiple disks on one USB interface are refused.")
        if candidates:
            block = candidates[0].resolve(strict=True)
            device = Path("/dev") / block.name
            try:
                identity = (block / "dev").read_text().strip()
                pinned = os.open(device, os.O_PATH | os.O_NOFOLLOW)
            except FileNotFoundError:
                time.sleep(0.2)
                continue
            try:
                valid = os.fstat(pinned)
                node = "{}:{}".format(os.major(valid.st_rdev), os.minor(valid.st_rdev))
                if not stat.S_ISBLK(valid.st_mode) or node != identity:
                    raise CheckError("Block device node does not match the selected USB interface.")
                _verify_unused(block, identity)
                fd = os.open("/proc/self/fd/{}".format(pinned), os.O_RDONLY | os.O_EXCL | os.O_NONBLOCK)
            finally:
                os.close(pinned)
            try:
                actual = os.fstat(fd)
                if not stat.S_ISBLK(actual.st_mode) or actual.st_rdev != valid.st_rdev:
                    raise CheckError("Block device changed before it was opened.")
                monitor()
                _verify_unused(block, identity)
                fcntl.ioctl(fd, BLKROSET, array.array("i", [1]))
                readonly = array.array("i", [0])
                fcntl.ioctl(fd, BLKROGET, readonly)
                if readonly[0] != 1:
                    raise CheckError("The kernel did not mark the USB disk read-only.")
                size = array.array("Q", [0])
                sector = array.array("i", [0])
                fcntl.ioctl(fd, BLKGETSIZE64, size)
                fcntl.ioctl(fd, BLKSSZGET, sector)
                if sector[0] not in (512, 1024, 2048, 4096) or not size[0] or size[0] % sector[0]:
                    raise CheckError("The selected USB disk has invalid geometry.")
                return fd, size[0], sector[0], block.name
            except BaseException:
                os.close(fd)
                raise
        time.sleep(0.2)
    raise CheckError("No eligible USB disk appeared. The system disk is excluded.")


def deauthorize(state):
    target = state["target"]
    if target and usb_snapshot().get(target["name"]) == target["identity"]:
        _write(USB / "devices" / target["name"] / "authorized", "0")


def restore_gate(state, confirmed=False):
    deauthorize(state)
    snapshot = usb_snapshot()
    has_new_devices = any(not HUB.fullmatch(name) and
                          state["baseline"].get(name) != identity
                          for name, identity in snapshot.items())
    if has_new_devices or (state["published"] and not confirmed):
        return False
    # Restore defaults after removal. Preserve unrelated operator changes.
    for entry in reversed(state["settings"]):
        path = Path(entry["path"])
        if path.exists() and path.read_text().strip() == "0":
            _write(path, entry["before"])
    if RULE.is_file():
        target = state["target"]
        expected = _rule_text(target["name"] if target else None)
        if RULE.read_text() not in (_rule_text(), expected):
            raise CheckError("An unexpected change to the USB Checker runtime rule needs manual review.")
        RULE.unlink()
    _reload_rules()
    if state["mask_intended"] and RUNTIME_MASK.is_symlink() and os.readlink(RUNTIME_MASK) == "/dev/null":
        command(["systemctl", "unmask", "--runtime", "udisks2.service"], timeout=20)
    if state["service_active"]:
        command(["systemctl", "start", "udisks2.service"], timeout=20)
    JOURNAL.unlink()
    return True
