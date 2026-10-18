#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("pic-up.py")
SPEC = importlib.util.spec_from_file_location("pic_up", MODULE_PATH)
assert SPEC and SPEC.loader
pic_up = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pic_up
SPEC.loader.exec_module(pic_up)


class FakeRunner:
    def __init__(self, rows: list[list[str]]) -> None:
        self.rows = rows

    def fields(self, fields: tuple[str, ...], display_filter: str | None = None) -> list[list[str]]:
        return self.rows


class MappingRunner:
    def __init__(self, rows: list[dict[str, str]]) -> None:
        self.rows = rows

    def fields(self, fields: tuple[str, ...], display_filter: str | None = None) -> list[list[str]]:
        return [[row.get(field, "") for field in fields] for row in self.rows]


class CryptoTests(unittest.TestCase):
    def test_repeating_xor_round_trip_and_key_formats(self) -> None:
        key = pic_up.parse_xor_key("hex:1c4ece63519493eb")
        plaintext = b"flag{known_plaintext_attack}"
        ciphertext = pic_up.repeating_xor(plaintext, key)
        self.assertEqual(pic_up.repeating_xor(ciphertext, key), plaintext)
        self.assertEqual(pic_up.parse_xor_key("base64:HE7OY1GUk+s="), key)
        self.assertEqual(pic_up.parse_xor_key("secret"), b"secret")

    def test_minimal_period(self) -> None:
        self.assertEqual(pic_up.minimal_period(b"ABCABCABC"), b"ABC")
        self.assertEqual(pic_up.minimal_period(b"ABCA"), b"ABCA")

    def test_rc4_known_vector(self) -> None:
        self.assertEqual(pic_up.rc4(b"Plaintext", b"Key").hex(), "bbf316e8d940af0ad3")

    def test_rc4_drop_preserves_round_trip(self) -> None:
        plaintext = b"bounded RC4-drop implementation"
        ciphertext = pic_up.rc4(plaintext, b"key", drop=4096)
        self.assertEqual(pic_up.rc4(ciphertext, b"key", drop=4096), plaintext)

    def test_auto_xor_recovers_writeup_key_and_flag(self) -> None:
        challenge = bytes.fromhex("704e34bbff99f3fe")
        response = bytes.fromhex("6c00fad8ae0d6015")
        ciphertext = bytes.fromhex(
            "502fee1138e7e3846f3aaf4334b3b38a"
            "7a28ab113cf5e7826a2fe24330f3f685"
            "682bee5329a0a1c73c27a24322e1fccb"
            "6c27af0d3eb4e08e712cbc0271e4f699"
            "7a2bba173eb8b3877d6eaf1625fbe182"
            "6634a7023cfbb38a3c3ebc0c32f1f78"
            "e6e2be0695bf2ff8a7b35a6530ef8a7"
            "b46e7ffb1361a1a4df3011a3570ee5e"
            "6df7011fd3c3da0cc8f2c23fa0d35a0"
            "ac961644"
        )
        packets = [
            pic_up.PayloadPacket(20, 1.0, 1, "server:12345", "agent:4042", 1, challenge),
            pic_up.PayloadPacket(21, 2.0, 1, "agent:4042", "server:12345", 1, response),
            pic_up.PayloadPacket(26, 3.0, 1, "server:12345", "agent:4042", 9, ciphertext),
        ]
        findings, blobs = pic_up.detect_repeating_xor(packets, 10)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["key_hex"], "1c4ece63519493eb")
        self.assertEqual(findings[0]["known_frames"], [20, 21])
        self.assertIn("flag{h0_l4_r15p0574,_m4_qu4l_3_l4_d0m4nd4?}", blobs[0][1].decode())


class ReassemblyTests(unittest.TestCase):
    def test_tcp_reassembly_removes_retransmission_and_overlap(self) -> None:
        segments = [(100, 1, b"hello "), (100, 2, b"hello "), (104, 3, b"o world")]
        self.assertEqual(pic_up.reassemble_tcp_segments(segments), [b"hello world"])

    def test_stream_inventory_is_direction_aware(self) -> None:
        rows = [
            ["5", "1.0", "7", "10.0.0.1", "", "12345", "10.0.0.2", "", "4444", "100", "68656c6c6f"],
            ["6", "1.1", "7", "10.0.0.2", "", "4444", "10.0.0.1", "", "12345", "900", "776f726c64"],
        ]
        streams, packets, blobs = pic_up.tcp_stream_inventory(FakeRunner(rows), 10)
        self.assertEqual(len(streams), 1)
        self.assertEqual(streams[0]["stream"], 7)
        self.assertEqual(streams[0]["payload_bytes"], 10)
        self.assertEqual(len(streams[0]["directions"]), 2)
        self.assertEqual(len(packets), 2)
        self.assertEqual({data for _, data in blobs}, {b"hello", b"world"})


class NetworkAnalyzerTests(unittest.TestCase):
    def test_tshark_field_catalog_keeps_optional_columns_aligned(self) -> None:
        runner = object.__new__(pic_up.Tshark)
        runner.display_filter = None
        runner.available_fields = lambda: {"frame.number", "tls.handshake.ja3"}
        runner.run = lambda arguments, include_filter=False: SimpleNamespace(stdout="12\tabc123\n")
        rows = runner.fields(("frame.number", "tls.handshake.ja4", "tls.handshake.ja3"))
        self.assertEqual(rows, [["12", "", "abc123"]])

    def test_udp_inventory_preserves_datagram_boundaries(self) -> None:
        runner = MappingRunner([
            {"frame.number": "2", "frame.time_epoch": "1.25", "udp.stream": "3", "ip.src": "10.0.0.1", "udp.srcport": "5353", "ip.dst": "10.0.0.2", "udp.dstport": "9999", "udp.length": "13", "udp.payload": "68656c6c6f"},
            {"frame.number": "3", "frame.time_epoch": "1.50", "udp.stream": "3", "ip.src": "10.0.0.2", "udp.srcport": "9999", "ip.dst": "10.0.0.1", "udp.dstport": "5353", "udp.length": "13", "udp.payload": "776f726c64"},
        ])
        sessions, blobs = pic_up.udp_stream_inventory(runner, 10)
        self.assertEqual(sessions[0]["datagrams"], 2)
        self.assertEqual(sessions[0]["payload_bytes"], 10)
        self.assertEqual([blob for _, blob in blobs], [b"hello", b"world"])

    def test_timeline_is_normalized_and_capped(self) -> None:
        runner = MappingRunner([
            {"frame.number": "1", "frame.time_epoch": "1700000000.5", "frame.len": "60", "frame.protocols": "eth:ip:tcp:http", "ip.src": "192.0.2.1", "ip.dst": "198.51.100.2", "tcp.srcport": "40000", "tcp.dstport": "80", "_ws.col.Info": "GET / HTTP/1.1"},
            {"frame.number": "2", "frame.time_epoch": "1700000001", "frame.len": "70"},
        ])
        events, total = pic_up.timeline_inventory(runner, 1)
        self.assertEqual(total, 2)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["transport"], "TCP")
        self.assertEqual(events[0]["time_utc"], "2023-11-14T22:13:20.500000Z")

    def test_credentials_are_redacted_and_hashed_by_default(self) -> None:
        runner = MappingRunner([{
            "frame.number": "9", "ip.src": "192.0.2.2", "ip.dst": "192.0.2.3",
            "ftp.request.command": "PASS", "ftp.request.arg": "supersecret",
        }])
        credentials = pic_up.credential_inventory(runner, 10)
        self.assertEqual(credentials[0]["value"], "<redacted>")
        self.assertTrue(credentials[0]["redacted"])
        self.assertEqual(len(credentials[0]["sha256"]), 64)

    def test_iocs_include_provenance(self) -> None:
        runner = MappingRunner([{
            "frame.number": "7", "frame.time_epoch": "100", "ip.src": "192.0.2.10",
            "ip.dst": "198.51.100.20", "dns.qry.name": "example.test",
            "http.host": "example.test", "http.request.uri": "/index",
        }])
        iocs = pic_up.ioc_inventory(runner, 10)
        domain = next(item for item in iocs if item["type"] == "domain")
        self.assertEqual(domain["value"], "example.test")
        self.assertIn(7, domain["frames"])
        self.assertTrue(any(item["type"] == "url" for item in iocs))


class DecoderAndScannerTests(unittest.TestCase):
    def test_capture_detection_requires_real_magic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_capture = Path(directory) / "fake.pcap"
            fake_capture.write_bytes(b"this is not packet data")
            self.assertFalse(pic_up.is_capture(fake_capture))

    def test_decompression_output_is_bounded(self) -> None:
        original_limit = pic_up.MAX_BLOB_BYTES
        try:
            pic_up.MAX_BLOB_BYTES = 64
            compressed = pic_up.zlib.compress(b"A" * 4096)
            decoded = list(pic_up.one_layer_decodings(compressed))
        finally:
            pic_up.MAX_BLOB_BYTES = original_limit
        self.assertFalse(any(encoding == "zlib" for encoding, _ in decoded))

    def test_default_artifact_root_skips_file_collision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "sample.bin"
            evidence.write_bytes(b"data")
            (root / "sample_picup").write_text("collision", encoding="utf-8")
            self.assertEqual(pic_up.default_artifact_root(evidence), root / "sample_picup_2")

    def test_base64_decoding(self) -> None:
        variants = dict(pic_up.decoded_variants(b"ZmxhZ3tuZXN0ZWRfZGVjb2Rpbmd9"))
        self.assertIn(b"flag{nested_decoding}", variants.values())

    def test_scan_finds_flag_in_xor_variant(self) -> None:
        key = b"key"
        ciphertext = pic_up.repeating_xor(b"prefix flag{xor_scan_works} suffix", key)
        variants = pic_up.xor_blob_variants([("stream", ciphertext)], key)
        matches = pic_up.scan_matches(variants, flag_prefix=None, patterns=[], rc4_key=None, rc4_drop=0)
        self.assertTrue(any(match.value == "flag{xor_scan_works}" for match in matches))

    def test_invalid_regex_is_reported(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid pattern"):
            pic_up.scan_matches([], flag_prefix=None, patterns=["("], rc4_key=None, rc4_drop=0)


class CliTests(unittest.TestCase):
    def test_generic_file_json_report_with_xor_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = bytes.fromhex("01020304")
            evidence = root / "evidence.bin"
            evidence.write_bytes(pic_up.repeating_xor(b"flag{cli_xor_success}", key))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = pic_up.main([
                    str(evidence), "--xor-key", "hex:01020304", "--json", "--no-ocr",
                    "--output-dir", str(root / "artifacts"),
                ])
            self.assertEqual(exit_code, 0)
            report = json.loads(output.getvalue())
            self.assertTrue(any(item["value"] == "flag{cli_xor_success}" for item in report["matches"]))
            self.assertEqual(report["streams"], [])


if __name__ == "__main__":
    unittest.main()
