#!/usr/bin/env python3

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "HIDGrabber.py"
sys.path.insert(0, str(ROOT))


def load_tool():
    specification = importlib.util.spec_from_file_location("hidgrabber", TOOL)
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


hidgrabber = load_tool()
from hid_database import LAYOUTS, USAGE_NAMES


def report(frame, payload, timestamp=None):
    return hidgrabber.HIDReport(
        frame=frame,
        timestamp=float(frame if timestamp is None else timestamp),
        bus="1",
        device="2",
        endpoint="0x81",
        transfer_type="0x01",
        data_length=len(payload),
        payload=payload,
        source_field="unit",
    )


def key_report(keycode=0, modifier=0):
    return bytes((modifier, 0, keycode, 0, 0, 0, 0, 0))


def typed_reports(sequence):
    output = []
    frame = 1
    for modifier, keycode in sequence:
        output.append(report(frame, key_report(keycode, modifier)))
        output.append(report(frame + 1, key_report(0, modifier)))
        frame += 2
    output.append(report(frame, key_report()))
    return output


class DatabaseTests(unittest.TestCase):
    def test_capture_detection_requires_magic_not_only_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_capture = Path(directory) / "not-a-capture.pcap"
            fake_capture.write_text("plain text", encoding="utf-8")
            self.assertFalse(hidgrabber.capture_magic(fake_capture))

    def test_complete_usage_database_and_layouts(self):
        self.assertEqual(len(USAGE_NAMES), 256)
        self.assertEqual(set(LAYOUTS), {"us", "uk", "it"})
        self.assertEqual(USAGE_NAMES[0x04], "A")
        self.assertEqual(USAGE_NAMES[0xE7], "RIGHT_GUI")

    def test_report_serialization_uses_prefixed_hex_and_converts_keys(self):
        item = hidgrabber.serialize_hid_report(report(7, key_report(0x04, 0x02)))
        self.assertEqual(item["dump"], "0x02 0x00 0x04 0x00 0x00 0x00 0x00 0x00")
        self.assertEqual(item["values"][2], "0x04")
        self.assertEqual(item["keyboard"]["modifier_names"], ["LEFT_SHIFT"])
        self.assertEqual(item["keyboard"]["keys"][0]["usage"], "A")


class KeyboardTests(unittest.TestCase):
    def test_duplicate_state_backspace_shift_and_caps(self):
        reports = [
            report(1, key_report(0x04)),
            report(2, key_report(0x04)),
            report(3, key_report()),
            report(4, key_report(0x05)),
            report(5, key_report()),
            report(6, key_report(0x2A)),
            report(7, key_report()),
            report(8, key_report(0x06, 0x02)),
            report(9, key_report()),
            report(10, key_report(0x39)),
            report(11, key_report()),
            report(12, key_report(0x07)),
            report(13, key_report()),
        ]
        decodings, events, _ = hidgrabber.decode_keyboards(reports, "us", True)
        self.assertEqual(decodings[0]["text"], "aCD")
        self.assertEqual(sum(event.keycode == 0x04 for event in events), 1)

    def test_alt_code(self):
        reports = [
            report(1, key_report(0x5E, 0x04)),
            report(2, key_report(0, 0x04)),
            report(3, key_report(0x5D, 0x04)),
            report(4, key_report(0, 0x04)),
            report(5, key_report()),
        ]
        decodings, events, _ = hidgrabber.decode_keyboards(reports, "us", True)
        self.assertEqual(decodings[0]["text"], "A")
        self.assertTrue(any(event.usage == "ALT_CODE" for event in events))

    def test_windows_alt_code_with_leading_zero(self):
        reports = []
        frame = 1
        for keycode in (0x62, 0x59, 0x5A, 0x60):
            reports.append(report(frame, key_report(keycode, 0x04)))
            reports.append(report(frame + 1, key_report(0, 0x04)))
            frame += 2
        reports.append(report(frame, key_report()))
        decodings, _, _ = hidgrabber.decode_keyboards(reports, "us", True)
        self.assertEqual(decodings[0]["text"], "€")

    def test_italian_layout_and_altgr(self):
        reports = typed_reports(((0, 0x2F), (0x40, 0x33), (0x02, 0x38)))
        decodings, _, _ = hidgrabber.decode_keyboards(reports, "it", True)
        self.assertEqual(decodings[0]["text"], "è@_")


class EncodingTests(unittest.TestCase):
    def test_generic_ctf_token_matches_without_prefix(self):
        matches = hidgrabber.find_matches((("unit", "RR{custom_prefix}"),), None, ())
        self.assertTrue(any(item["value"] == "RR{custom_prefix}" for item in matches))

    def test_hex_utf16le(self):
        expected = "flag{utf16_ok}"
        typed = expected.encode("utf-16-le").hex()
        results = hidgrabber.decode_layers(typed, "auto")
        self.assertTrue(any(item["text"] == expected for item in results))
        self.assertTrue(any("utf-16-le" in item["chain"] for item in results if item["text"] == expected))

    def test_nested_base64_utf8(self):
        encoded = "ZmxhZ3tiYXNlNjRfb2t9"
        results = hidgrabber.decode_layers(encoded, "auto")
        self.assertTrue(any(item["text"] == "flag{base64_ok}" for item in results))

    def test_binary_utf8(self):
        encoded = " ".join(f"{byte:08b}" for byte in b"flag{binary_ok}")
        results = hidgrabber.decode_layers(encoded, "auto")
        self.assertTrue(any(item["text"] == "flag{binary_ok}" for item in results))


class MouseTests(unittest.TestCase):
    def test_signed_coordinates_and_svg(self):
        reports = [report(1, bytes((1, 5, 255, 0))), report(2, bytes((0, 2, 3, 0)))]
        events = hidgrabber.decode_mouse(reports, set(), False)
        self.assertEqual((events[-1].x, events[-1].y), (7, 2))
        self.assertIn("<svg", hidgrabber.mouse_svg(events))


@unittest.skipUnless(shutil.which("tshark") and shutil.which("capinfos"), "TShark is required")
class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from scapy.all import Raw, wrpcap
            from scapy.layers.usb import USBpcap, USBpcapTransferInterrupt
        except ImportError as error:
            raise unittest.SkipTest("Scapy USB layers are required") from error
        cls.temporary = tempfile.TemporaryDirectory()
        cls.capture = Path(cls.temporary.name) / "keyboard.pcap"
        packets = []
        sequence = [
            (0, 0x09), (0, 0x0F), (0, 0x04), (0, 0x0A),
            (0x02, 0x2F), (0x02, 0x0B), (0x02, 0x0C), (0x02, 0x07),
            (0x02, 0x2D), (0, 0x23), (0, 0x22), (0x02, 0x30),
        ]
        encoded_text = "ZmxhZ3tlbmNvZGVkfQ=="
        for character in encoded_text:
            for keycode, (plain, shifted) in LAYOUTS["us"]["keys"].items():
                if character == plain:
                    sequence.append((0, keycode))
                    break
                if character == shifted:
                    sequence.append((0x02, keycode))
                    break
            else:
                raise AssertionError(f"missing synthetic key mapping for {character!r}")
        cls.expected_plaintext = "flag{HID_65}" + encoded_text
        cls.expected_events = len(sequence)
        timestamp = 1.0
        for modifier, keycode in sequence:
            for raw in (key_report(keycode, modifier), key_report(keycode, modifier), key_report(0, modifier)):
                packet = (
                    USBpcap(
                        headerLen=39, function=9, info=1, bus=1, device=2,
                        endpoint=0x81, transfer=1, dataLength=8,
                    )
                    / USBpcapTransferInterrupt()
                    / Raw(raw)
                )
                packet.time = timestamp
                timestamp += 0.01
                packets.append(packet)
        wrpcap(str(cls.capture), packets)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_full_cli_sha_reports_and_plaintext(self):
        output = Path(self.temporary.name) / "output"
        result = subprocess.run(
            [
                sys.executable, str(TOOL), str(self.capture), "--json",
                "--layout", "us", "--flag-prefix", "flag", "--output-dir", str(output),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertRegex(data["file"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(data["hid_reports"][0]["dump"], "0x00 0x00 0x09 0x00 0x00 0x00 0x00 0x00")
        self.assertEqual(data["hid_reports"][0]["keyboard"]["keys"][0]["usage"], "F")
        self.assertEqual(data["keyboard"][0]["text"], self.expected_plaintext)
        self.assertTrue(any(item["value"] == "flag{HID_65}" for item in data["matches"]))
        self.assertTrue(any(item["text"] == "flag{encoded}" for item in data["decoded_encodings"]))
        self.assertEqual(data["inventory"]["keyboard_events"], self.expected_events)
        self.assertTrue((output / "decoded.txt").is_file())
        self.assertTrue((output / "hid-reports.csv").is_file())
        self.assertTrue((output / "keyboard-events.csv").is_file())
        self.assertTrue((output / "report.json").is_file())

    def test_all_checks_everything_without_writing_files(self):
        working_directory = Path(self.temporary.name) / "no-output"
        working_directory.mkdir()
        result = subprocess.run(
            [sys.executable, str(TOOL), str(self.capture), "--all", "--json"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=working_directory,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["mode"], "all")
        self.assertIsNone(data["output_directory"])
        self.assertEqual(data["artifacts"], [])
        self.assertTrue(any("--all active" in note for note in data["diagnostics"]))
        self.assertEqual(list(working_directory.iterdir()), [])

    def test_cli_prints_dump_before_every_conversion_without_flag_prefix(self):
        result = subprocess.run(
            [sys.executable, str(TOOL), str(self.capture), "--layout", "auto", "--no-color"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        dump_position = result.stdout.index("━━ HID HEXADECIMAL DUMP")
        conversion_position = result.stdout.index("━━ CONVERTED HID VALUES")
        plaintext_position = result.stdout.index("━━ RECOVERED PLAINTEXT")
        self.assertLess(dump_position, conversion_position)
        self.assertLess(conversion_position, plaintext_position)
        self.assertIn("0x00 0x00 0x09 0x00 0x00 0x00 0x00 0x00", result.stdout)
        self.assertIn("key=0x09 usage=F", result.stdout)
        self.assertIn("flag{HID_65}", result.stdout)
        self.assertIn("━━ DECODED ENCODINGS", result.stdout)
        self.assertIn("flag{encoded}", result.stdout)
        self.assertIn("layout=us", result.stdout)
        self.assertIn("layout=uk", result.stdout)
        self.assertIn("layout=it", result.stdout)


if __name__ == "__main__":
    unittest.main()
