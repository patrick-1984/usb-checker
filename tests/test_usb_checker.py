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
    def test_replacement_requires_new_unique_unauthorized_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            port = root / "devices" / "4-1"
            port.mkdir(parents=True)
            (port / "authorized").write_text("0")
            state = {"target": {"name": "7-1", "identity": ["2", 197910]}}
            current = {"4-1": ["2", 200173]}
            with patch.object(usb, "USB", root), patch.object(usb, "new_devices", return_value=current):
                self.assertEqual(cli.replacement_device(state), ["4-1", ["2", 200173]])
                current["7-1"] = ["2", 197910]
                with self.assertRaisesRegex(CheckError, "one new USB"):
                    cli.replacement_device(state)
                del current["4-1"]
                with self.assertRaisesRegex(CheckError, "still connected"):
                    cli.replacement_device(state)

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
                patch.object(cli, "launch_case") as launch, self.assertRaisesRegex(CheckError, "Only an incomplete held"):
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


class DirectScanTests(unittest.TestCase):
    def test_sandbox_refuses_system_disk_identity_before_opening(self):
        entry = Mock(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 0))
        with patch.object(scanner.os, "stat", return_value=entry), patch("builtins.open") as opened:
            with self.assertRaisesRegex(CheckError, "different block device"):
                scanner.verify_device("8:0")
            opened.assert_not_called()

    def test_scan_passes_the_exact_read_only_device_and_creates_only_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            monitor = Mock()
            response = Mock(stdout='{"findings":[],"limitations":[],"selected_files":2}')
            node = Mock(st_rdev=os.makedev(8, 16))
            with patch.object(cli, "sandbox", return_value=response) as sandbox, patch.object(cli.os, "fstat", return_value=node):
                report = cli.scan_device(root, 42, "sdb", 51200, 512, monitor)
            sandbox.assert_called_once_with(
                "/proc/{}/fd/42".format(os.getpid()), ["512", "51200", "8:16"],
                device="/dev/sdb", unit="usb-check-scan-" + root.name, monitor=monitor,
            )
            self.assertEqual(report["verdict"], "nothing-found")
            self.assertEqual({item.name for item in root.iterdir()}, {"status.json", "report.json", "report.txt"})

    def test_direct_check_marks_sandbox_failure_as_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            node = Mock(st_rdev=os.makedev(8, 16))
            with patch.object(cli, "sandbox", side_effect=CheckError("No read-only bind")), patch.object(cli.os, "fstat", return_value=node):
                report = cli.scan_device(root, 42, "sdb", 51200, 512, Mock())
            self.assertEqual((report["verdict"], report["coverage"]), ("review", "partial"))


class ReportTests(unittest.TestCase):
    def test_discarded_candidates_consume_attempt_and_byte_budgets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            limits = []

            def tool(args, *, size=0, destination=None, **kwargs):
                if destination is None:
                    return 0, "r/r 1: one\nr/r 2: two\nr/r 3: three\n", ""
                limits.append(size)
                destination.write_bytes(b"x" * size)
                return 1, "", "over limit"

            with patch.multiple(scanner, STAGE_LIMIT=7, FILE_LIMIT=5, FILE_COUNT=2, tool=tool), \
                    patch.object(scanner, "Path", side_effect=lambda path: root / Path(path).name):
                samples, issues = {}, []
                attempted, extracted = scanner.collect_files(512, [], issues, [], samples)
            self.assertEqual((attempted, extracted), (2, 7))
            self.assertEqual(limits, [5, 2])
            self.assertFalse(samples)
            self.assertTrue(any("budget" in item for item in issues))

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
