"""Flags inherit decoder and structural provenance instead of prefix-only trust."""

import base64
from fixture_support import load_module


def test_flag_only_after_decoder_is_linked():
    decoders = load_module("src.payload_decoder"); hunter = load_module("src.flag_hunter")
    encoded = base64.b64encode(b"FLAG{decoded_only}")
    payload = next(x for x in decoders.decode_payloads(b"x=" + encoded) if x["decoder"] == "base64")
    flags = hunter.hunt_flags([{"data": payload["decoded"], "source": "encoded.txt", "decoder": "base64", "confidence": .8, "chain": ["input", "base64"]}], ["FLAG"])
    assert flags[0]["value"] == "FLAG{decoded_only}" and flags[0]["decoder"] == "base64"

