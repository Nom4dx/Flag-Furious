import base64
import io

from picup_web.scanner import ScanConfig, scan_bytes, scan_stream


def test_flag_split_between_chunks():
    data = b"A" * 31 + b"picoCTF{split_across_chunks}" + b"Z"
    found = scan_stream(io.BytesIO(data), source="fixture", path="raw", module="scan", config=ScanConfig(), chunk_size=40)
    assert any(x.value == "picoCTF{split_across_chunks}" for x in found)


def test_base64_token_and_no_result():
    encoded = base64.b64encode(b"flag{from_shell_history}")
    found = scan_bytes(b"echo " + encoded + b" | base64 -d", source="shell", path=".bash_history", module="history", config=ScanConfig())
    assert any(x.value == "flag{from_shell_history}" and "base64" in x.method for x in found)
    assert scan_bytes(b"ordinary content", source="x", path="x", module="scan", config=ScanConfig()) == []


def test_utf16_and_xor():
    flag = "HTB{wide_value}"
    assert any(x.value == flag for x in scan_bytes(flag.encode("utf-16be"), source="x", path="x", module="scan", config=ScanConfig()))
    raw = bytes(x ^ 0x42 for x in b"picoCTF{xor_value}")
    assert any(x.value == "picoCTF{xor_value}" and "xor" in x.method for x in scan_bytes(raw, source="x", path="x", module="scan", config=ScanConfig()))

