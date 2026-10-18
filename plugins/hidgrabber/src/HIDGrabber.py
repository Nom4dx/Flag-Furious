#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import json
import os
import re
import selectors
import signal
import shutil
import subprocess
import sys
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence
from app.core.bounded_process import run_bounded

sys.dont_write_bytecode = True

from hid_database import KEYPAD_DIGITS, KEYPAD_TEXT, LAYOUTS, MODIFIERS, SPECIAL_ACTIONS, USAGE_NAMES


VERSION = "1.2.0"
TEXT_ENCODINGS = (
    "utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be",
    "utf-32", "utf-32-le", "utf-32-be", "utf-7", "ascii", "latin-1",
    "cp1252", "cp850", "mac-roman",
)
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_TSHARK_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_TSHARK_ROWS = 50_000
MAX_TSHARK_LINE_BYTES = 64 * 1024

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "green": "\033[92m", "red": "\033[31m",
    "cyan": "\033[96m", "yellow": "\033[33m", "magenta": "\033[95m",
    "blue": "\033[34m", "white": "\033[37m", "dim": "\033[2m",
}


@dataclass(frozen=True, slots=True)
class HIDReport:
    frame: int
    timestamp: float
    bus: str
    device: str
    endpoint: str
    transfer_type: str
    data_length: int
    payload: bytes
    source_field: str

    @property
    def channel(self) -> str:
        return f"bus {self.bus or '?'} / device {self.device or '?'} / endpoint {self.endpoint or '?'}"


@dataclass(frozen=True, slots=True)
class KeyEvent:
    frame: int
    timestamp: float
    channel: str
    modifier: int
    modifier_names: tuple[str, ...]
    keycode: int
    usage: str
    rendered: str
    action: str


@dataclass(frozen=True, slots=True)
class MouseEvent:
    frame: int
    timestamp: float
    channel: str
    buttons: int
    x_delta: int
    y_delta: int
    wheel: int
    x: int
    y: int


def paint(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{ANSI[color]}{text}{ANSI['reset']}"


def section(title: str, colors: bool) -> None:
    print()
    print(paint(f"━━ {title.upper()} {'━' * max(2, 66 - len(title))}", "cyan", colors))


def terminal_text(value: str) -> str:
    return "".join(
        character if character in "\r\n\t" or ord(character) >= 32 else f"\\x{ord(character):02x}"
        for character in value
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def parse_hex(value: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    if not cleaned or len(cleaned) % 2:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def prefixed_hex(data: bytes) -> str:
    return " ".join(f"0x{value:02x}" for value in data)


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def parse_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def capture_magic(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        return False
    return magic in {
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
    }


def capture_info(path: Path, *, hash_file: bool = True) -> dict[str, Any]:
    info: dict[str, Any] = {
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "sha256": sha256_file(path) if hash_file else None,
    }
    result = run_bounded(["capinfos", "-M", str(path)], timeout=10,
                         max_stdout=256 * 1024, max_stderr=64 * 1024)
    if result["timed_out"]:
        info.setdefault("diagnostics", []).append("capinfos ha superato il timeout di 10 secondi")
    elif result["truncated"]:
        info.setdefault("diagnostics", []).append("capinfos ha superato il limite di output")
    elif result["returncode"] != 0:
        info.setdefault("diagnostics", []).append("capinfos non disponibile o ha rifiutato il capture")
    wanted = {
        "File type": "format", "File encapsulation": "encapsulation",
        "Number of packets": "packets", "Capture duration": "duration",
        "First packet time": "first_packet", "Last packet time": "last_packet",
        "Strict time order": "strict_time_order",
    }
    if result["returncode"] == 0 and not result["truncated"] and not result["timed_out"]:
        for line in result["stdout"].decode("utf-8", "replace").splitlines():
            if ":" not in line:
                continue
            name, value = (part.strip() for part in line.split(":", 1))
            if name in wanted:
                info[wanted[name]] = value
    return info


class Tshark:
    def __init__(self, capture: Path, display_filter: str | None, timeout: int) -> None:
        self.capture = capture
        self.display_filter = display_filter
        self.timeout = timeout
        self.truncated = False
        self.stop_reason = ""

    def fields(self, names: Sequence[str], display_filter: str) -> list[list[str]]:
        effective_filter = display_filter
        if self.display_filter:
            effective_filter = f"({self.display_filter}) && ({display_filter})"
        command = [
            "tshark", "-n", "-r", str(self.capture), "-Y", effective_filter,
            "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
        ]
        for name in names:
            command.extend(("-e", name))
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError as error:
            raise RuntimeError(f"TShark non avviabile: {error}") from error
        rows = []
        buffer = bytearray()
        consumed = 0
        deadline = time.monotonic() + self.timeout

        def add_line(line):
            values = line.decode("utf-8", "replace").rstrip("\r").split("\t")
            values.extend([""] * (len(names) - len(values)))
            rows.append(values[:len(names)])

        try:
            assert process.stdout is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self.truncated = True
                        self.stop_reason = "timeout"
                        break
                    if not selector.select(remaining):
                        self.truncated = True
                        self.stop_reason = "timeout"
                        break
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    consumed += len(chunk)
                    if consumed > MAX_TSHARK_OUTPUT_BYTES:
                        self.truncated = True
                        self.stop_reason = "byte limit"
                        break
                    buffer.extend(chunk)
                    while True:
                        newline = buffer.find(b"\n")
                        if newline < 0:
                            if len(buffer) > MAX_TSHARK_LINE_BYTES:
                                self.truncated = True
                                self.stop_reason = "line limit"
                            break
                        if newline > MAX_TSHARK_LINE_BYTES:
                            self.truncated = True
                            self.stop_reason = "line limit"
                        else:
                            add_line(bytes(buffer[:newline]))
                        del buffer[:newline + 1]
                        if self.truncated or len(rows) >= MAX_TSHARK_ROWS:
                            self.truncated = True
                            if not self.stop_reason:
                                self.stop_reason = "row limit"
                            break
                    if self.truncated:
                        break
            if not self.truncated and buffer:
                if len(buffer) <= MAX_TSHARK_LINE_BYTES and len(rows) < MAX_TSHARK_ROWS:
                    add_line(bytes(buffer))
                else:
                    self.truncated = True
                    self.stop_reason = "line limit or row limit"
        finally:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait()
            elif process.poll() not in (0, None) and not self.truncated:
                raise RuntimeError("TShark failed")
        return rows


def extract_hid_reports(runner: Tshark) -> tuple[list[HIDReport], list[str]]:
    fields = (
        "frame.number", "frame.time_epoch", "usb.bus_id", "usb.device_address",
        "usb.endpoint_address", "usb.transfer_type", "usb.data_len", "usb.capdata",
        "usb.data_fragment", "usbhid.data",
    )
    display_filter = "usb.capdata || usb.data_fragment || usbhid.data"
    reports: list[HIDReport] = []
    diagnostics: list[str] = []
    trimmed_headers: Counter[int] = Counter()
    seen: set[tuple[int, str, bytes]] = set()
    for row in runner.fields(fields, display_filter):
        candidates = (("usbhid.data", row[9]), ("usb.data_fragment", row[8]), ("usb.capdata", row[7]))
        source_field = ""
        payload = b""
        for candidate_name, candidate_value in candidates:
            decoded = parse_hex(candidate_value)
            if decoded:
                source_field = candidate_name
                payload = decoded
                break
        if not payload:
            continue
        data_length = parse_int(row[6], len(payload))
        if data_length > 0 and len(payload) > data_length:
            removed = len(payload) - data_length
            payload = payload[-data_length:]
            trimmed_headers[removed] += 1
        # Frame numbers are capture-global, but endpoints are reused by separate
        # USB devices. Keep the full channel/transfer identity in the key.
        key = (parse_int(row[0]), row[2], row[3], row[4], row[5], payload)
        if key in seen:
            continue
        seen.add(key)
        reports.append(HIDReport(
            frame=parse_int(row[0]), timestamp=parse_float(row[1]), bus=row[2],
            device=row[3], endpoint=row[4], transfer_type=row[5],
            data_length=data_length, payload=payload, source_field=source_field,
        ))
    reports.sort(key=lambda item: (item.timestamp, item.frame))
    for removed, count in trimmed_headers.most_common():
        diagnostics.append(f"removed {removed} USB capture-header byte(s) from {count} report(s)")
    if runner.truncated:
        diagnostics.append(f"TShark stopped at {runner.stop_reason}; HID report is partial")
    return reports, list(dict.fromkeys(diagnostics))


def keyboard_payload(payload: bytes) -> tuple[int | None, bytes] | None:
    if len(payload) == 8:
        return None, payload
    if len(payload) == 9:
        return payload[0], payload[1:9]
    if len(payload) > 9:
        candidate = payload[-8:]
        if candidate[1] == 0:
            return None, candidate
    return None


def mouse_payload(payload: bytes) -> tuple[int | None, bytes] | None:
    if len(payload) in {3, 4}:
        return None, payload
    if len(payload) == 5:
        return payload[0], payload[1:]
    return None


def modifier_names(modifier: int) -> tuple[str, ...]:
    return tuple(name for bit, name in MODIFIERS.items() if modifier & bit)


def serialize_hid_report(report: HIDReport) -> dict[str, Any]:
    item: dict[str, Any] = {
        "frame": report.frame,
        "timestamp": report.timestamp,
        "channel": report.channel,
        "bus": report.bus,
        "device": report.device,
        "endpoint": report.endpoint,
        "transfer_type": report.transfer_type,
        "data_length": report.data_length,
        "source_field": report.source_field,
        "hex": report.payload.hex(),
        "dump": prefixed_hex(report.payload),
        "values": [f"0x{value:02x}" for value in report.payload],
    }
    keyboard = keyboard_payload(report.payload)
    if keyboard:
        report_id, raw = keyboard
        modifier = raw[0]
        item["keyboard"] = {
            "report_id": f"0x{report_id:02x}" if report_id is not None else None,
            "modifier": f"0x{modifier:02x}",
            "modifier_names": list(modifier_names(modifier)),
            "reserved": f"0x{raw[1]:02x}",
            "keys": [
                {"slot": slot, "value": f"0x{keycode:02x}", "usage": USAGE_NAMES.get(keycode, f"UNKNOWN_0x{keycode:02X}")}
                for slot, keycode in enumerate(raw[2:8], start=1)
            ],
        }
    mouse = mouse_payload(report.payload)
    if mouse:
        report_id, raw = mouse
        item["mouse"] = {
            "report_id": f"0x{report_id:02x}" if report_id is not None else None,
            "buttons": f"0x{raw[0]:02x}",
            "left": bool(raw[0] & 0x01),
            "right": bool(raw[0] & 0x02),
            "middle": bool(raw[0] & 0x04),
            "x_delta": signed_byte(raw[1]),
            "y_delta": signed_byte(raw[2]),
            "wheel": signed_byte(raw[3]) if len(raw) >= 4 else 0,
        }
    return item


class KeyboardDecoder:
    def __init__(self, layout: str, keep_actions: bool) -> None:
        self.layout = layout
        self.keep_actions = keep_actions
        self.previous_keys: set[int] = set()
        self.previous_modifier = 0
        self.caps_lock = False
        self.num_lock = True
        self.alt_digits = ""
        self.output: list[str] = []
        self.events: list[KeyEvent] = []

    def _append(self, value: str) -> None:
        if value:
            self.output.append(value)

    def _backspace(self) -> None:
        if self.output:
            self.output.pop()

    def _flush_alt_code(self, report: HIDReport) -> None:
        if not self.alt_digits:
            return
        value = int(self.alt_digits)
        encoding = "unicode"
        if value <= 255:
            encoding = "cp1252" if self.alt_digits.startswith("0") else "cp437"
            try:
                rendered = bytes((value,)).decode(encoding)
            except UnicodeDecodeError:
                rendered = chr(value)
        else:
            rendered = chr(value) if value <= 0x10FFFF else f"[ALT_CODE_{self.alt_digits}]"
        self._append(rendered)
        self.events.append(KeyEvent(
            report.frame, report.timestamp, report.channel, self.previous_modifier,
            modifier_names(self.previous_modifier), 0, "ALT_CODE", rendered,
            f"decimal Alt code {self.alt_digits} ({encoding})",
        ))
        self.alt_digits = ""

    def _render_key(self, keycode: int, modifier: int) -> tuple[str, str]:
        shift = bool(modifier & 0x22)
        ctrl = bool(modifier & 0x11)
        left_alt = bool(modifier & 0x04)
        right_alt = bool(modifier & 0x40)
        gui = bool(modifier & 0x88)
        layout = LAYOUTS[self.layout]
        if right_alt and keycode in layout["altgr"]:
            value = layout["altgr"][keycode]
        elif keycode in layout["keys"]:
            plain, shifted = layout["keys"][keycode]
            if plain.isalpha() and len(plain) == 1 and plain.isascii():
                value = plain.upper() if shift ^ self.caps_lock else plain.lower()
            else:
                value = shifted if shift else plain
        elif keycode in SPECIAL_ACTIONS:
            value = SPECIAL_ACTIONS[keycode]
        elif keycode in KEYPAD_TEXT:
            value = KEYPAD_TEXT[keycode]
        else:
            value = f"[{USAGE_NAMES.get(keycode, f'0x{keycode:02X}')} ]".replace(" ]", "]")
        action = "text"
        clean_value = value.strip() or USAGE_NAMES.get(keycode, "KEY")
        if ctrl:
            value, action = f"[CTRL+{clean_value.upper()}]", "shortcut"
        elif gui:
            value, action = f"[GUI+{clean_value.upper()}]", "shortcut"
        elif left_alt:
            value, action = f"[ALT+{clean_value.upper()}]", "shortcut"
        elif value.startswith("["):
            action = "special"
        return value, action

    def process(self, report: HIDReport, raw: bytes) -> None:
        modifier = raw[0]
        keys = [key for key in raw[2:8] if key]
        current_keys = set(keys)
        if any(key in {0x01, 0x02, 0x03} for key in keys):
            self.events.append(KeyEvent(
                report.frame, report.timestamp, report.channel, modifier,
                modifier_names(modifier), keys[0], USAGE_NAMES[keys[0]], "", "rollover error",
            ))
            self.previous_keys = current_keys
            self.previous_modifier = modifier
            return
        left_alt_was_down = bool(self.previous_modifier & 0x04)
        left_alt_is_down = bool(modifier & 0x04)
        if left_alt_was_down and not left_alt_is_down:
            self._flush_alt_code(report)
        new_keys = [key for key in keys if key not in self.previous_keys]
        for keycode in new_keys:
            usage = USAGE_NAMES.get(keycode, f"UNKNOWN_0x{keycode:02X}")
            if keycode == 0x39:
                self.caps_lock = not self.caps_lock
                rendered, action = "", f"caps lock {'on' if self.caps_lock else 'off'}"
            elif keycode == 0x53:
                self.num_lock = not self.num_lock
                rendered, action = "", f"num lock {'on' if self.num_lock else 'off'}"
            elif left_alt_is_down and keycode in KEYPAD_DIGITS:
                self.alt_digits += KEYPAD_DIGITS[keycode]
                rendered, action = "", f"Alt-code digit {KEYPAD_DIGITS[keycode]}"
            elif keycode == 0x2A:
                self._backspace()
                rendered, action = "", "backspace applied"
            else:
                rendered, action = self._render_key(keycode, modifier)
                if action == "text" or self.keep_actions or not rendered.startswith("["):
                    self._append(rendered)
            self.events.append(KeyEvent(
                report.frame, report.timestamp, report.channel, modifier,
                modifier_names(modifier), keycode, usage, rendered, action,
            ))
        self.previous_keys = current_keys
        self.previous_modifier = modifier

    def finish(self, report: HIDReport | None) -> tuple[str, list[KeyEvent]]:
        if report and self.alt_digits:
            self._flush_alt_code(report)
        return "".join(self.output), self.events


def text_score(text: str) -> float:
    if not text:
        return -1000.0
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text)
    score = printable * 20
    score += len(re.findall(r"[A-Za-z0-9]{3,}", text))
    score += 40 * len(re.findall(r"(?i)(?:flag|ctf|HTB|picoCTF)\{[^}]+\}", text))
    score += 8 * text.count("{") if text.count("{") == text.count("}") else -5
    score -= 3 * text.count("[RESERVED_")
    return score


def decode_keyboards(
    reports: Sequence[HIDReport], layout_option: str, keep_actions: bool,
) -> tuple[list[dict[str, Any]], list[KeyEvent], set[int]]:
    grouped: dict[str, list[tuple[HIDReport, bytes]]] = defaultdict(list)
    keyboard_frames: set[int] = set()
    for report in reports:
        candidate = keyboard_payload(report.payload)
        if candidate is None:
            continue
        _, raw = candidate
        if raw[1] != 0:
            continue
        grouped[report.channel].append((report, raw))
        keyboard_frames.add(report.frame)
    decodings: list[dict[str, Any]] = []
    selected_events: list[KeyEvent] = []
    layouts = tuple(LAYOUTS) if layout_option == "auto" else (layout_option,)
    for channel, items in grouped.items():
        candidates = []
        event_sets: dict[str, list[KeyEvent]] = {}
        for layout in layouts:
            decoder = KeyboardDecoder(layout, keep_actions)
            for report, raw in items:
                decoder.process(report, raw)
            text, events = decoder.finish(items[-1][0] if items else None)
            candidates.append({"layout": layout, "text": text, "score": round(text_score(text), 3)})
            event_sets[layout] = events
        best = max(candidates, key=lambda item: item["score"])
        selected_events.extend(event_sets[best["layout"]])
        decodings.append({
            "channel": channel, "selected_layout": best["layout"],
            "text": best["text"], "layout_candidates": candidates,
            "report_count": len(items), "event_count": len(event_sets[best["layout"]]),
        })
    return decodings, selected_events, keyboard_frames


def signed_byte(value: int) -> int:
    return value - 256 if value > 127 else value


def decode_mouse(reports: Sequence[HIDReport], excluded_frames: set[int], include_all: bool) -> list[MouseEvent]:
    states: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))
    events: list[MouseEvent] = []
    for report in reports:
        if report.frame in excluded_frames and not include_all:
            continue
        candidate = mouse_payload(report.payload)
        if candidate is None:
            continue
        _, raw = candidate
        x_delta, y_delta = signed_byte(raw[1]), signed_byte(raw[2])
        wheel = signed_byte(raw[3]) if len(raw) >= 4 else 0
        x, y = states[report.channel]
        x += x_delta
        y += y_delta
        states[report.channel] = (x, y)
        events.append(MouseEvent(
            report.frame, report.timestamp, report.channel, raw[0],
            x_delta, y_delta, wheel, x, y,
        ))
    return events


def decoded_texts(data: bytes, encoding_option: str) -> Iterable[tuple[str, str]]:
    encodings = TEXT_ENCODINGS if encoding_option == "auto" else (encoding_option,)
    seen: set[str] = set()
    for encoding in encodings:
        if encoding == "utf-8-sig" and not data.startswith(b"\xef\xbb\xbf"):
            continue
        if encoding == "utf-16" and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
            continue
        if encoding == "utf-32" and not data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            continue
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        if not text or text in seen:
            continue
        seen.add(text)
        readable = sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text)
        c1_controls = sum(0x80 <= ord(character) <= 0x9F for character in text)
        if readable >= 0.85 and c1_controls == 0:
            yield encoding, text


def encoded_byte_candidates(text: str) -> Iterable[tuple[str, bytes]]:
    raw = text.encode("utf-8", errors="ignore")[:MAX_TEXT_BYTES]
    for token in re.findall(rb"(?i)(?:0x[0-9a-f]{2}[\s,;:_-]*){2,}", raw):
        yield "0x-bytes", bytes(int(value, 16) for value in re.findall(rb"(?i)0x([0-9a-f]{2})", token))
    for token in re.findall(rb"(?i)(?:\\x[0-9a-f]{2}){2,}", raw):
        yield "escaped-bytes", bytes(int(value, 16) for value in re.findall(rb"(?i)\\x([0-9a-f]{2})", token))
    for token in re.findall(rb"(?<![01])(?:[01]{8}[\s:_-]*){2,}(?![01])", raw):
        octets = re.findall(rb"[01]{8}", token)
        yield "binary", bytes(int(value, 2) for value in octets)
    for token in re.findall(rb"(?i)(?<![0-9a-f])[0-9a-f]{8,}(?![0-9a-f])", raw):
        if len(token) % 2 == 0:
            try:
                yield "hex", bytes.fromhex(token.decode())
            except ValueError:
                pass
    for token in re.findall(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/])", raw):
        try:
            decoded = base64.b64decode(token + b"=" * ((4 - len(token) % 4) % 4), validate=True)
        except (ValueError, binascii.Error):
            continue
        if decoded:
            yield "base64", decoded
    for token in re.findall(rb"(?i)(?<![a-z2-7])[a-z2-7]{8,}(?![a-z2-7])", raw):
        try:
            decoded = base64.b32decode(token.upper() + b"=" * ((8 - len(token) % 8) % 8))
        except (ValueError, binascii.Error):
            continue
        if decoded:
            yield "base32", decoded
    for token in re.findall(r"(?:%[0-9a-fA-F]{2}){2,}", text):
        yield "url", urllib.parse.unquote_to_bytes(token)


def decode_layers(text: str, encoding_option: str, max_depth: int = 3) -> list[dict[str, Any]]:
    queue: list[tuple[str, str, int]] = [("HID plaintext", text, 0)]
    seen_text = {text}
    seen_bytes: set[bytes] = set()
    results: list[dict[str, Any]] = []
    while queue:
        chain, current, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for transport, data in encoded_byte_candidates(current):
            digest = hashlib.sha256(data).digest()
            if digest in seen_bytes:
                continue
            seen_bytes.add(digest)
            for encoding, decoded in decoded_texts(data, encoding_option):
                if decoded in seen_text or decoded == current:
                    continue
                seen_text.add(decoded)
                next_chain = f"{chain} → {transport} → {encoding}"
                results.append({
                    "chain": next_chain, "text": decoded,
                    "byte_length": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                })
                queue.append((next_chain, decoded, depth + 1))
    results.sort(key=lambda item: text_score(item["text"]), reverse=True)
    return results


def compile_flag_pattern(prefix: str | Sequence[str] | None) -> re.Pattern[str]:
    prefixes = [prefix] if isinstance(prefix, str) else list(prefix or [])
    bases = [re.escape(item.rstrip("{")) for item in prefixes if item]
    if bases:
        base = "(?:" + "|".join(bases) + ")"
        expression = base + r"(?:\{[^}\r\n]{1,512}\}|[:=_-][A-Za-z0-9_./+\-=]{4,512})"
    else:
        expression = (
            r"(?:[A-Za-z][A-Za-z0-9_-]{0,31}\{[^}\r\n]{1,512}\}|"
            r"(?:flag|ctf|HTB|THM|picoCTF)(?:[:=_-][A-Za-z0-9_./+\-=]{4,512}))"
        )
    return re.compile(expression, re.IGNORECASE)


def find_matches(
    texts: Iterable[tuple[str, str]],
    flag_prefix: str | Sequence[str] | None,
    patterns: Sequence[str],
) -> list[dict[str, str]]:
    flag_pattern = compile_flag_pattern(flag_prefix)
    compiled = []
    for value in patterns:
        try:
            compiled.append((value, re.compile(value, re.IGNORECASE)))
        except re.error as error:
            raise ValueError(f"invalid pattern {value!r}: {error}") from error
    output = []
    seen = set()
    for source, text in texts:
        for match in flag_pattern.finditer(text):
            key = ("flag", match.group())
            if key not in seen:
                seen.add(key)
                output.append({"kind": "flag", "value": match.group(), "source": source})
        for name, pattern in compiled:
            for match in pattern.finditer(text):
                key = (name, match.group())
                if key not in seen:
                    seen.add(key)
                    output.append({"kind": f"pattern:{name}", "value": match.group(), "source": source})
    return output


def file_type(path: Path) -> str:
    if not shutil.which("file"):
        return "unknown"
    result = run_bounded(["file", "-b", str(path)], timeout=5, max_stdout=4096, max_stderr=4096)
    if result["returncode"] != 0 or result["truncated"] or result["timed_out"]:
        return "unknown"
    return result["stdout"].decode("utf-8", "replace").strip() or "unknown"


def write_reports_csv(path: Path, reports: Sequence[HIDReport]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(("frame", "time_epoch", "bus", "device", "endpoint", "transfer_type", "length", "source_field", "hex", "0x_dump"))
        for item in reports:
            writer.writerow((item.frame, f"{item.timestamp:.9f}", item.bus, item.device, item.endpoint, item.transfer_type, len(item.payload), item.source_field, item.payload.hex(), prefixed_hex(item.payload)))


def write_key_events_csv(path: Path, events: Sequence[KeyEvent]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(("frame", "time_epoch", "channel", "modifier_hex", "modifiers", "keycode_hex", "usage", "rendered", "action"))
        for item in events:
            writer.writerow((item.frame, f"{item.timestamp:.9f}", item.channel, f"0x{item.modifier:02x}", "+".join(item.modifier_names), f"0x{item.keycode:02x}", item.usage, item.rendered, item.action))


def write_mouse_csv(path: Path, events: Sequence[MouseEvent]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(("frame", "time_epoch", "channel", "buttons", "dx", "dy", "wheel", "x", "y"))
        for item in events:
            writer.writerow((item.frame, f"{item.timestamp:.9f}", item.channel, item.buttons, item.x_delta, item.y_delta, item.wheel, item.x, item.y))


def mouse_svg(events: Sequence[MouseEvent]) -> str:
    if not events:
        return ""
    xs, ys = [item.x for item in events], [item.y for item in events]
    minimum_x, maximum_x = min(xs), max(xs)
    minimum_y, maximum_y = min(ys), max(ys)
    padding = 20
    width = max(100, maximum_x - minimum_x + padding * 2)
    height = max(100, maximum_y - minimum_y + padding * 2)
    all_points = " ".join(f"{item.x - minimum_x + padding},{item.y - minimum_y + padding}" for item in events)
    drawing_segments: list[list[str]] = []
    active: list[str] = []
    for item in events:
        point = f"{item.x - minimum_x + padding},{item.y - minimum_y + padding}"
        if item.buttons & 0x01:
            active.append(point)
        elif active:
            drawing_segments.append(active)
            active = []
    if active:
        drawing_segments.append(active)
    red_paths = "\n".join(
        f'<polyline points="{" ".join(points)}" fill="none" stroke="#ef4444" stroke-width="2"/>'
        for points in drawing_segments if len(points) >= 2
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">\n<rect width="100%" height="100%" fill="#0b1020"/>\n'
        f'<polyline points="{all_points}" fill="none" stroke="#64748b" stroke-width="1" opacity="0.6"/>\n'
        f'{red_paths}\n</svg>\n'
    )


def decoder_reports(reports: Sequence[HIDReport], include_non_interrupt: bool, include_outbound: bool) -> tuple[list[HIDReport], list[str]]:
    selected = []
    ignored_non_interrupt = 0
    ignored_outbound = 0
    for report in reports:
        transfer = parse_int(report.transfer_type, -1)
        endpoint = parse_int(report.endpoint, -1)
        if not include_non_interrupt and transfer not in {-1, 1}:
            ignored_non_interrupt += 1
            continue
        if not include_outbound and endpoint >= 0 and not endpoint & 0x80:
            ignored_outbound += 1
            continue
        selected.append(report)
    notes = []
    if ignored_non_interrupt:
        notes.append(f"ignored {ignored_non_interrupt} non-interrupt USB data report(s); use --include-non-interrupt to decode them")
    if ignored_outbound:
        notes.append(f"ignored {ignored_outbound} outbound USB report(s); use --include-outbound to decode them")
    return selected, notes


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    info = capture_info(args.pcap, hash_file=not getattr(args, "skip_hash", False))
    diagnostics = list(info.pop("diagnostics", []))
    runner = Tshark(args.pcap, args.display_filter, args.timeout)
    reports, tshark_diagnostics = extract_hid_reports(runner)
    diagnostics.extend(tshark_diagnostics)
    if args.all:
        diagnostics.append("--all active: every layout, text encoding, HID decoder, transfer type, and endpoint direction was checked")
    usable_reports, selection_notes = decoder_reports(reports, args.include_non_interrupt, args.include_outbound)
    diagnostics.extend(selection_notes)
    if args.device_type == "mouse":
        keyboard_decodings, key_events, keyboard_frames = [], [], set()
    else:
        keyboard_decodings, key_events, keyboard_frames = decode_keyboards(usable_reports, args.layout, not args.clean)
    mouse_events = []
    if args.device_type in {"auto", "mouse", "all"}:
        mouse_events = decode_mouse(usable_reports, keyboard_frames, args.device_type == "all")

    text_sources: list[tuple[str, str]] = []
    layered: list[dict[str, Any]] = []
    for decoding in keyboard_decodings:
        for candidate in decoding["layout_candidates"]:
            source = f"{decoding['channel']} ({candidate['layout']} layout)"
            text_sources.append((source, candidate["text"]))
            for item in decode_layers(candidate["text"], args.encoding):
                item["source"] = source
                layered.append(item)
                text_sources.append((f"{source}: {item['chain']}", item["text"]))
    matches = find_matches(text_sources, args.flag_prefix, args.pattern)

    output = args.output_dir.resolve() if args.output_dir else None
    artifacts: list[dict[str, Any]] = []
    report_path: Path | None = None
    if output:
        if output == args.pcap.resolve():
            raise ValueError("output directory cannot replace the source capture")
        output.mkdir(parents=True, exist_ok=True)
        decoded_path = output / "decoded.txt"
        reports_path = output / "hid-reports.csv"
        events_path = output / "keyboard-events.csv"
        mouse_path = output / "mouse-events.csv"
        svg_path = output / "mouse-path.svg"
        report_path = output / "report.json" if not getattr(args, "no_report_file", False) else None
        decoded_sections = []
        for item in keyboard_decodings:
            for candidate in item["layout_candidates"]:
                marker = "selected" if candidate["layout"] == item["selected_layout"] else "candidate"
                decoded_sections.append(
                    f"[{item['channel']} | layout={candidate['layout']} | {marker}]\n{candidate['text']}"
                )
        if layered:
            decoded_sections.append("[DECODED ENCODING LAYERS]\n" + "\n".join(f"{item['chain']}: {item['text']}" for item in layered))
        decoded_path.write_text("\n\n".join(decoded_sections) + ("\n" if decoded_sections else ""), encoding="utf-8")
        write_reports_csv(reports_path, reports)
        write_key_events_csv(events_path, key_events)
        write_mouse_csv(mouse_path, mouse_events)
        svg = mouse_svg(mouse_events)
        if svg:
            svg_path.write_text(svg, encoding="utf-8")
        for path in (decoded_path, reports_path, events_path, mouse_path):
            artifacts.append({"path": str(path.resolve()), "size": path.stat().st_size, "sha256": sha256_file(path), "type": file_type(path)})
        if svg:
            artifacts.append({"path": str(svg_path.resolve()), "size": svg_path.stat().st_size, "sha256": sha256_file(svg_path), "type": file_type(svg_path)})
    if not reports:
        diagnostics.append("No HID payload was found in usb.capdata, usb.data_fragment, or usbhid.data")
    if reports and not keyboard_decodings and not mouse_events:
        diagnostics.append("USB data was found, but no supported Boot Keyboard/Boot Mouse report shape was recognized")
    report: dict[str, Any] = {
        "tool": {"name": "HIDGrabber", "version": VERSION},
        "mode": "all" if args.all else "standard",
        "file": info,
        "output_directory": str(output) if output else None,
        "inventory": {
            "hid_reports": len(reports), "keyboard_channels": len(keyboard_decodings),
            "keyboard_events": len(key_events), "mouse_events": len(mouse_events),
            "channels": dict(Counter(item.channel for item in reports)),
        },
        "hid_reports": [serialize_hid_report(item) for item in reports],
        "keyboard": keyboard_decodings,
        "key_events": [asdict(item) for item in key_events],
        "mouse": [asdict(item) for item in mouse_events],
        "decoded_encodings": layered,
        "matches": matches,
        "artifacts": artifacts,
        "diagnostics": list(dict.fromkeys(diagnostics)),
    }
    if report_path:
        report["report_path"] = str(report_path.resolve())
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def print_report(report: dict[str, Any], colors: bool) -> None:
    print(paint(f"HIDGrabber {VERSION} — CTF USB HID Triage", "magenta", colors))
    section("Input", colors)
    info = report["file"]
    for key in ("path", "format", "encapsulation", "size", "packets", "first_packet", "last_packet", "duration", "sha256"):
        if key in info:
            color = "blue" if key == "sha256" else "white"
            print(paint(f"[•] {key:<18} {info[key]}", color, colors))
    print(paint(f"[=] mode               {report['mode']}", "yellow" if report["mode"] == "all" else "blue", colors))
    if report["output_directory"]:
        print(paint(f"[+] artifacts          {report['output_directory']}", "green", colors))
    else:
        print(paint("[—] artifacts          disabled (use --output-dir DIR to write files)", "dim", colors))

    inventory = report["inventory"]
    section("HID hexadecimal dump", colors)
    if report["hid_reports"]:
        print(paint(
            f"[=] reports={inventory['hid_reports']} channels={len(inventory['channels'])} "
            f"keyboard-events={inventory['keyboard_events']} mouse-events={inventory['mouse_events']}",
            "blue", colors,
        ))
        for item in report["hid_reports"]:
            print(paint(
                f"[0x] frame={item['frame']} time={item['timestamp']:.9f} len={len(item['values'])} "
                f"field={item['source_field']} | {item['channel']}",
                "yellow", colors,
            ))
            print(paint(f"     {item['dump']}", "white", colors))
    else:
        print(paint("[—] No HID byte values found.", "dim", colors))

    section("Converted HID values", colors)
    converted = False
    for item in report["hid_reports"]:
        keyboard = item.get("keyboard")
        if keyboard:
            converted = True
            modifiers = "+".join(keyboard["modifier_names"]) or "none"
            active_keys = [
                f"{key['value']}={key['usage']}"
                for key in keyboard["keys"] if key["value"] != "0x00"
            ]
            keys = ", ".join(active_keys) if active_keys else "release/no key"
            report_id = f" report-id={keyboard['report_id']}" if keyboard["report_id"] else ""
            print(paint(
                f"[KBD] frame={item['frame']}{report_id} modifier={keyboard['modifier']} ({modifiers}) "
                f"reserved={keyboard['reserved']} | {keys}",
                "blue", colors,
            ))
        mouse = item.get("mouse")
        if mouse:
            converted = True
            pressed = "+".join(
                name for name, active in (("left", mouse["left"]), ("right", mouse["right"]), ("middle", mouse["middle"]))
                if active
            ) or "none"
            report_id = f" report-id={mouse['report_id']}" if mouse["report_id"] else ""
            print(paint(
                f"[MOUSE] frame={item['frame']}{report_id} buttons={mouse['buttons']} ({pressed}) "
                f"dx={mouse['x_delta']:+d} dy={mouse['y_delta']:+d} wheel={mouse['wheel']:+d}",
                "blue", colors,
            ))
    for item in report["key_events"]:
        converted = True
        modifiers = "+".join(item["modifier_names"]) or "none"
        rendered = terminal_text(item["rendered"]) if item["rendered"] else "—"
        print(paint(
            f"[→] frame={item['frame']} key=0x{item['keycode']:02x} usage={item['usage']} "
            f"modifier=0x{item['modifier']:02x} ({modifiers}) → {rendered} | {item['action']}",
            "green", colors,
        ))
    for item in report["mouse"]:
        converted = True
        print(paint(
            f"[→] frame={item['frame']} mouse cumulative=({item['x']},{item['y']}) "
            f"delta=({item['x_delta']:+d},{item['y_delta']:+d}) wheel={item['wheel']:+d} buttons=0x{item['buttons']:02x}",
            "green", colors,
        ))
    if not converted:
        print(paint("[—] No supported keyboard or mouse conversion available.", "dim", colors))

    section("Recovered plaintext", colors)
    if report["keyboard"]:
        for item in report["keyboard"]:
            print(paint(f"[KEYBOARD] {item['channel']} | layout={item['selected_layout']}", "green", colors))
            for candidate in item["layout_candidates"]:
                selected = candidate["layout"] == item["selected_layout"]
                marker = "OK" if selected else "?"
                color = "green" if selected else "yellow"
                print(paint(f"[{marker}] layout={candidate['layout']} score={candidate['score']}", color, colors))
                print(terminal_text(candidate["text"]) if candidate["text"] else paint("[empty]", "dim", colors))
    else:
        print(paint("[—] No keyboard plaintext reconstructed.", "dim", colors))

    if report["decoded_encodings"]:
        section("Decoded encodings", colors)
        for item in report["decoded_encodings"]:
            print(paint(f"[DECODE] {item['chain']}", "yellow", colors))
            print(paint(f"         source: {item['source']} | bytes={item['byte_length']} sha256={item['sha256']}", "dim", colors))
            print(terminal_text(item["text"]))

    section("CTF matches", colors)
    if report["matches"]:
        for item in report["matches"]:
            print(paint(f"[OK] {item['kind']}: {item['value']}", "green", colors))
            print(paint(f"     {item['source']}", "dim", colors))
    else:
        print(paint("[—] No flag or requested pattern found.", "dim", colors))

    if report["mouse"]:
        section("Mouse", colors)
        last = report["mouse"][-1]
        print(paint(f"[MOUSE] {len(report['mouse'])} event(s), final position=({last['x']}, {last['y']})", "cyan", colors))
        if report["output_directory"]:
            print(paint("[MOUSE] See mouse-events.csv and mouse-path.svg in the output directory.", "green", colors))
        else:
            print(paint("[MOUSE] Use --output-dir DIR to write mouse-events.csv and mouse-path.svg.", "dim", colors))

    if report["artifacts"]:
        section("Artifacts", colors)
        for item in report["artifacts"]:
            print(paint(f"[+] {item['path']} | {item['size']} bytes", "green", colors))
            print(paint(f"    sha256 {item['sha256']}", "blue", colors))
    if report["diagnostics"]:
        section("Notes", colors)
        for note in report["diagnostics"]:
            print(paint(f"[i] {note}", "blue", colors))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="HIDGrabber",
        description="Extract and decode USB HID keyboard/mouse reports from PCAP and PCAPNG files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  HIDGrabber capture.pcapng
  HIDGrabber capture.pcapng --all
  HIDGrabber capture.pcapng --all --output-dir ./hid-artifacts
  HIDGrabber capture.pcapng --layout it -f flag
  HIDGrabber mouse.pcapng --device-type mouse
  HIDGrabber capture.pcapng -Y 'usb.device_address == 4'

File behavior:
  No file is created by default, including with --all or --json. Pass
  --output-dir DIR explicitly to write decoded text, CSV, SVG, and report.json.
""",
    )
    parser.add_argument("pcap", type=Path, help="PCAP or PCAPNG capture to analyze")
    parser.add_argument("--all", action="store_true", help="check every layout, encoding, HID decoder, USB transfer type, and endpoint direction")
    parser.add_argument("-o", "--output-dir", type=Path, metavar="DIR", help="write decoded text, CSV, mouse SVG, and JSON report to DIR; disabled by default")
    parser.add_argument("--layout", choices=("auto", *LAYOUTS), default="auto", help="keyboard layout (default: auto tries US, UK, IT)")
    parser.add_argument("--device-type", choices=("auto", "keyboard", "mouse", "all"), default="auto", help="HID decoder selection")
    parser.add_argument("--encoding", choices=("auto", *TEXT_ENCODINGS), default="auto", help="encoding for nested typed data (default: auto)")
    parser.add_argument("-f", "--flag-prefix", action="append", help="expected flag prefix; repeat for multiple prefixes")
    parser.add_argument("-p", "--pattern", action="append", default=[], metavar="REGEX", help="extra case-insensitive regex; repeatable")
    parser.add_argument("-Y", "--filter", dest="display_filter", help="additional Wireshark display filter")
    parser.add_argument("--include-non-interrupt", action="store_true", help="also decode USB transfer types other than interrupt")
    parser.add_argument("--include-outbound", action="store_true", help="also decode host-to-device USB reports")
    parser.add_argument("--clean", action="store_true", help="omit non-text special-key markers from reconstructed plaintext")
    parser.add_argument("--timeout", type=int, default=120, help="TShark timeout in seconds (default: 120)")
    parser.add_argument("--skip-hash", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--force", action="store_true", help="allow use of a non-empty --output-dir")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON on standard output; does not create files")
    parser.add_argument("--no-report-file", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="color mode (default: auto)")
    parser.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.pcap.is_file():
        parser.error(f"capture not found: {args.pcap}")
    if not capture_magic(args.pcap):
        parser.error(f"input is not recognized as PCAP/PCAPNG: {args.pcap}")
    if not shutil.which("tshark") or not shutil.which("capinfos"):
        parser.error("HIDGrabber requires tshark and capinfos")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.force and not args.output_dir:
        parser.error("--force requires --output-dir")
    if args.output_dir and args.output_dir.exists():
        if not args.output_dir.is_dir():
            parser.error(f"output path is not a directory: {args.output_dir}")
        if any(args.output_dir.iterdir()) and not args.force:
            parser.error(f"output directory is not empty: {args.output_dir} (use --force)")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.all:
        args.layout = "auto"
        args.device_type = "all"
        args.encoding = "auto"
        args.include_non_interrupt = True
        args.include_outbound = True
        args.clean = False
    validate(args, parser)
    colors = not args.json and not args.no_color and (
        args.color == "always" or (args.color == "auto" and sys.stdout.isatty())
    )
    try:
        report = analyze(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(paint(f"[ERROR] {error}", "red", colors), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report, colors)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
