import hashlib
import os
import stat
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

from usb_checker import cli, scanner, usb
from usb_checker.common import CheckError, write_json


def descriptor(interfaces, *, device_class=0):
    config = bytearray([9, 2, 0, 0, len(interfaces), 1, 0, 0x80, 20])
    for number, alternate, kind, subclass, protocol in interfaces:
        config.extend([9, 4, number, alternate, 2, kind, subclass, protocol, 0])
        config.extend([7, 5, 0x81, 2, 64, 0, 0])
        config.extend([7, 5, 0x02, 2, 64, 0, 0])
    config[2:4] = len(config).to_bytes(2, "little")
    return bytes([18, 1, 0, 2, device_class, 0, 0, 64,
                  0x12, 0x34, 0x56, 0x78, 0, 1, 1, 2, 3, 1]) + config


class DescriptorTests(unittest.TestCase):
    def test_storage_accepted_and_digest_preserved(self):
        raw = descriptor([(0, 0, 8, 6, 0x50)])
        details, interface = usb.parse_descriptors(raw)
        self.assertEqual(interface, "1.0")
        self.assertEqual(details["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(details["interfaces"][0]["class"], 8)

    def test_pure_hid_and_composite_classes_are_refused_and_reported(self):
        for interfaces, classes in [
            ([(0, 0, 3, 1, 1)], [3]),
            ([(0, 0, 8, 6, 0x50), (1, 0, 3, 1, 1)], [8, 3]),
        ]:
            with self.subTest(classes=classes):
                details, interface = usb.parse_descriptors(descriptor(interfaces))
                self.assertIsNone(interface)
                self.assertEqual([item["class"] for item in details["interfaces"]], classes)

    def test_unknown_protocol_and_alternate_fall_closed(self):
        for interface in [(0, 0, 8, 6, 0x62), (0, 1, 8, 6, 0x50), (0, 0, 2, 6, 0)]:
            self.assertIsNone(usb.parse_descriptors(descriptor([interface]))[1])

    def test_truncated_descriptor_rejected(self):
        raw = descriptor([(0, 0, 8, 6, 0x50)])
        with self.assertRaises(CheckError):
            usb.parse_descriptors(raw[:-1])


class GateTests(unittest.TestCase):
    def test_resume_uses_original_held_gate_and_one_unauthorized_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device = root / "devices" / "1-2"
            device.mkdir(parents=True)
            (device / "authorized").write_text("0")
            state = {"case": root.name, "published": True, "target": None}
            identity = ["7", 123]
            with patch.object(usb, "USB", root), patch.object(cli, "read_json", return_value=state), \
                    patch.object(usb, "new_devices", return_value={"1-2": identity}) as current:
                self.assertEqual(cli.resume_state(root), (state, ["1-2", identity]))
                current.assert_called_once_with(state)
                current.return_value["1-3"] = ["8", 124]
                with self.assertRaisesRegex(CheckError, "exactly one"):
                    cli.resume_state(root)
                del current.return_value["1-3"]
                (device / "authorized").write_text("1")
                with self.assertRaisesRegex(CheckError, "unauthorized"):
                    cli.resume_state(root)

    def test_resume_cannot_replace_existing_result(self):
        state = {"phase": "held", "held_reason": "insertion-timeout", "result": {"verdict": "refused"}}
        with patch.object(cli, "lock", return_value=nullcontext()), patch.object(cli, "status", return_value=state), \
                patch.object(cli, "launch_case") as launch, self.assertRaisesRegex(CheckError, "Only a held"):
            cli.resume(Path("case"))
        launch.assert_not_called()

    def test_duplicate_removal_cannot_apply_a_stale_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {"phase": "failed", "removal_confirmed": True}
            with patch.object(cli, "status", side_effect=[{"phase": "held"}, state]), \
                    patch.object(cli, "lock", return_value=nullcontext()), patch.object(usb, "restore_gate") as restore:
                self.assertEqual(cli.removed(root), state)
            restore.assert_not_called()

    def test_never_select_sda_or_preexisting_usb_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interface = root / "usb" / "1-1:1.0"
            interface.mkdir(parents=True)
            block = root / "block"
            block.mkdir()
            for disk in ("sda", "sdb", "sdc", "sdc1"):
                candidate = interface / disk
                candidate.mkdir()
                (block / disk).symlink_to(candidate)
            alien = root / "sdd"
            alien.mkdir()
            (block / "sdd").symlink_to(alien)
            with patch.object(usb, "BLOCK", block):
                self.assertEqual([item.name for item in usb._candidate_blocks(interface, ["sdb"])], ["sdc"])
            with self.assertRaisesRegex(CheckError, "system disk"):
                usb._verify_unused(interface / "sda", "8:0")
            with self.assertRaisesRegex(CheckError, "system disk"):
                usb._verify_unused(interface / "sda1", "8:1")

    def test_gate_stays_held_until_explicit_confirmation_and_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            setting = root / "default"
            setting.write_text("0\n")
            state = {
                "baseline": {"usb1": ["1", 9]}, "target": None, "published": True,
                "settings": [{"path": str(setting), "before": "-1"}],
                "mask_intended": False, "service_active": False,
            }
            journal = root / "gate"
            write_json(journal, state)
            with patch.multiple(usb, JOURNAL=journal, RULE=root / "rule"), patch.object(usb, "_reload_rules"):
                with patch.object(usb, "usb_snapshot", return_value={"usb1": ["1", 9], "1-2": ["2", 1]}):
                    self.assertFalse(usb.restore_gate(state, confirmed=True))
                with patch.object(usb, "usb_snapshot", return_value={"usb1": ["1", 9]}):
                    self.assertFalse(usb.restore_gate(state))
                    self.assertEqual(setting.read_text().strip(), "0")
                    self.assertTrue(usb.restore_gate(state, confirmed=True))
            self.assertFalse(journal.exists())
            self.assertEqual(setting.read_text().strip(), "-1")


class ImageTests(unittest.TestCase):
    def test_analyze_rejects_block_inode_without_opening_it_for_data(self):
        node = Mock(st_mode=stat.S_IFBLK)
        with patch.object(cli, "lock", return_value=nullcontext()), patch.object(cli.os, "open", return_value=42) as opened, \
                patch.object(cli.os, "fstat", return_value=node), patch.object(cli.os, "close"):
            with self.assertRaisesRegex(CheckError, "regular image"):
                cli.analyze(Path("/dev/sda"), 512)
        opened.assert_called_once_with(Path("/dev/sda"), os.O_PATH | os.O_NOFOLLOW)

    def test_read_only_image_hash_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            original = b"hello" * 2048
            source.write_bytes(original)
            with source.open("rb") as handle:
                image = cli.image_copy(root, handle.fileno(), len(original))
            self.assertEqual(image.read_bytes(), original)
            self.assertEqual(cli.status(root)["image_sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(image.stat().st_mode & 0o777, 0o444)

    def test_short_read_has_no_verified_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"x")
            with source.open("rb") as handle, self.assertRaisesRegex(CheckError, "advertised size"):
                cli.image_copy(root, handle.fileno(), 512)
            self.assertFalse((root / "image.raw").exists())
            self.assertNotIn("image_sha256", cli.status(root))


class ReportTests(unittest.TestCase):
    def test_report_limits_cannot_hide_later_clamav_signature(self):
        findings = [{"severity": "review"}] * scanner.REPORT_FINDINGS + [{"severity": "malicious"}]
        evidence = scanner.summarize_findings(findings)
        self.assertEqual(evidence["omitted_findings"], 1)
        self.assertEqual(evidence["findings"][0]["severity"], "malicious")
        with tempfile.TemporaryDirectory() as temporary:
            report = cli.write_report(Path(temporary), evidence)
        self.assertEqual(report["verdict"], "malicious")

    def test_partial_can_never_claim_nothing_found(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = cli.write_report(root, {"limitations": ["Definitions unavailable."], "findings": []})
            self.assertEqual((report["verdict"], report["coverage"]), ("review", "partial"))

    def test_high_confidence_beats_missing_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = cli.write_report(root, {"limitations": ["Partial archive."], "findings": [{"severity": "malicious"}]})
            self.assertEqual((report["verdict"], report["coverage"]), ("malicious", "partial"))

    def test_database_without_official_components_cannot_be_fresh(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = scanner.signature_status(Path(temporary), lambda _: self.fail("Missing DB was opened"))
            self.assertEqual(result["state"], "missing")

    def test_definition_age_is_taken_from_signed_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("main", "daily", "bytecode"):
                (root / (name + ".cvd")).touch()
            with patch.object(scanner, "time", return_value=1795262400):
                result = scanner.signature_status(root, lambda _: (0, "Build time: 20 Nov 2026 14-00 +0000\nVersion: 27001\n", ""))
            self.assertEqual(result["state"], "fresh")
            self.assertEqual(result["daily_version"], "27001")


if __name__ == "__main__":
    unittest.main()
