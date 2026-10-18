#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import math
import re
import shutil
import statistics
import stat
import tarfile
import struct
import subprocess
import sys
import urllib.parse
import zipfile
import zlib
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from picup.network import (
    credential_inventory,
    expert_inventory,
    ioc_inventory,
    protocol_details,
    timeline_inventory,
    udp_stream_inventory,
    write_timeline,
)


VERSION = "3.0.0"
MAX_BLOB_BYTES = 8 * 1024 * 1024
MAX_RAW_SCAN_BYTES = 128 * 1024 * 1024
DEFAULT_TOP = 15
MAX_CARVED_FILES = 500
MAX_ARCHIVE_MEMBERS = 1000
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
EXPORT_PROTOCOLS = ("http", "ftp-data", "smb", "tftp", "imf")
TLS_SECRET_LABELS = {
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EARLY_EXPORTER_SECRET",
    "EXPORTER_SECRET",
}

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[92m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "yellow": "\033[33m",
    "white": "\033[37m",
}


@dataclass(slots=True)
class Flow:
    protocol: str
    endpoint_a: str
    endpoint_b: str
    packets: int = 0
    bytes: int = 0
    first: float = 0.0
    last: float = 0.0
    timestamps: list[float] = field(default_factory=list, repr=False)

    @property
    def duration(self) -> float:
        return max(0.0, self.last - self.first)


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    category: str
    summary: str
    evidence: str


@dataclass(frozen=True, slots=True)
class Match:
    kind: str
    value: str
    source: str
    encoding: str = "plain"


@dataclass(frozen=True, slots=True)
class PayloadPacket:
    frame: int
    timestamp: float
    stream: int
    source: str
    destination: str
    sequence: int
    payload: bytes = field(repr=False)


@dataclass(slots=True)
class Report:
    file: dict[str, Any]
    protocols: list[dict[str, Any]]
    hosts: list[dict[str, Any]]
    conversations: list[dict[str, Any]]
    streams: list[dict[str, Any]]
    udp_streams: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    expert: list[dict[str, Any]]
    protocol_details: list[dict[str, Any]]
    credentials: list[dict[str, Any]]
    iocs: list[dict[str, Any]]
    xor: list[dict[str, Any]]
    dns: list[dict[str, Any]]
    http: list[dict[str, Any]]
    tls: list[dict[str, Any]]
    hostnames: list[dict[str, Any]]
    findings: list[Finding]
    matches: list[Match]
    exports: list[dict[str, Any]]
    comments: list[dict[str, Any]]
    covert: list[dict[str, Any]]
    images: list[dict[str, Any]]
    extracted_files: list[dict[str, Any]]
    log: dict[str, Any]
    diagnostics: list[str]


def paint(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{ANSI[color]}{text}{ANSI['reset']}"


def section(title: str, colors: bool) -> None:
    print()
    rule = "━" * max(2, 66 - len(title))
    print(paint(f"━━ {title.upper()} {rule}", "cyan", colors))


def safe_text(value: bytes | str, limit: int = 240) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = value
    text = "".join(character if character.isprintable() else "." for character in text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def parse_number(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_hex_bytes(value: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    if not cleaned or len(cleaned) % 2:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value.lower())
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def parse_rc4_key(value: str) -> bytes:
    if value.startswith("hex:"):
        try:
            key = bytes.fromhex(value[4:])
        except ValueError as error:
            raise ValueError("invalid hexadecimal RC4 key") from error
    elif value.startswith("base64:"):
        try:
            key = base64.b64decode(value[7:], validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("invalid Base64 RC4 key") from error
    else:
        key = value.encode()
    if not key:
        raise ValueError("the RC4 key cannot be empty")
    return key


def parse_xor_key(value: str) -> bytes:
    """Parse a repeating-XOR key using the same text/hex/Base64 syntax as RC4."""
    if value.startswith("hex:"):
        try:
            key = bytes.fromhex(value[4:])
        except ValueError as error:
            raise ValueError("invalid hexadecimal XOR key") from error
    elif value.startswith("base64:"):
        try:
            key = base64.b64decode(value[7:], validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("invalid Base64 XOR key") from error
    else:
        key = value.encode()
    if not key:
        raise ValueError("the XOR key cannot be empty")
    return key


def repeating_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("the XOR key cannot be empty")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def minimal_period(data: bytes) -> bytes:
    """Reduce a repeated byte string to its shortest exact period."""
    for length in range(1, len(data) + 1):
        if len(data) % length == 0 and data == data[:length] * (len(data) // length):
            return data[:length]
    return data


def rc4(data: bytes, key: bytes, drop: int = 0) -> bytes:
    if not key:
        raise ValueError("the RC4 key cannot be empty")
    if drop < 0:
        raise ValueError("--rc4-drop cannot be negative")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    for _ in range(drop):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


class Tshark:
    def __init__(
        self,
        capture: Path,
        *,
        display_filter: str | None = None,
        keylog: Path | None = None,
        rsa_key: Path | None = None,
        rsa_address: str = "0.0.0.0",
        rsa_port: int = 0,
        rsa_protocol: str = "http",
        timeout: int = 120,
    ) -> None:
        self.capture = capture
        self.display_filter = display_filter
        self.timeout = timeout
        self._field_catalog: set[str] | None = None
        self.preferences: list[str] = []
        if keylog:
            self.preferences.extend(("-o", f"tls.keylog_file:{keylog.resolve()}"))
        if rsa_key:
            key_spec = f"{rsa_address},{rsa_port},{rsa_protocol},{rsa_key.resolve()}"
            self.preferences.extend(("-o", f"tls.keys_list:{key_spec}"))

    def run(
        self,
        arguments: Sequence[str],
        *,
        include_filter: bool = True,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = ["tshark", "-n", "-r", str(self.capture), *self.preferences]
        if include_filter and self.display_filter:
            command.extend(("-Y", self.display_filter))
        command.extend(arguments)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"TShark timeout after {self.timeout}s") from error
        if check and result.returncode:
            message = result.stderr.strip() or result.stdout.strip() or "unknown TShark error"
            raise RuntimeError(message)
        return result

    def available_fields(self) -> set[str]:
        """Return fields supported by this TShark release.

        Field names evolve between Wireshark versions.  Discovering them once
        prevents one optional analyzer field from aborting an otherwise useful
        triage run.
        """
        if self._field_catalog is not None:
            return self._field_catalog
        try:
            result = subprocess.run(
                ["tshark", "-G", "fields"], capture_output=True, text=True,
                errors="replace", timeout=self.timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            self._field_catalog = set()
            return self._field_catalog
        catalog: set[str] = set()
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                columns = line.split("\t")
                if len(columns) > 2 and columns[0] == "F":
                    catalog.add(columns[2])
        self._field_catalog = catalog
        return catalog

    def fields(self, fields: Sequence[str], display_filter: str | None = None) -> list[list[str]]:
        requested = tuple(fields)
        catalog = self.available_fields()
        active = tuple(field for field in requested if not catalog or field in catalog)
        if not active:
            return []
        if display_filter in requested and catalog and display_filter not in catalog:
            return []
        arguments: list[str] = []
        effective_filter = self.display_filter
        if display_filter and effective_filter:
            effective_filter = f"({effective_filter}) && ({display_filter})"
        elif display_filter:
            effective_filter = display_filter
        if effective_filter:
            arguments.extend(("-Y", effective_filter))
        arguments.extend(("-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"))
        for field_name in active:
            arguments.extend(("-e", field_name))
        result = self.run(arguments, include_filter=False)
        rows: list[list[str]] = []
        for line in result.stdout.splitlines():
            values = line.split("\t")
            values.extend([""] * (len(active) - len(values)))
            by_name = dict(zip(active, values))
            rows.append([by_name.get(field, "") for field in requested])
        return rows

    def count(self, display_filter: str | None = None) -> int:
        return len(self.fields(("frame.number",), display_filter))


def is_capture(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        return False
    return magic in {
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
    }


def is_tls_keylog(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            prefix = handle.read(1024 * 1024)
    except OSError:
        return False
    for line in prefix.splitlines():
        fields = line.strip().split()
        if len(fields) == 3 and fields[0] in TLS_SECRET_LABELS:
            return True
    return False


def validate_inputs(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.input.is_file():
        parser.error(f"input file not found: {args.input}")
    if args.output_dir and args.output_dir.exists():
        if not args.output_dir.is_dir():
            parser.error(f"output path is not a directory: {args.output_dir}")
        if any(args.output_dir.iterdir()) and not args.force:
            parser.error(f"output directory is not empty: {args.output_dir} (use --force)")
    args.input_kind = "capture" if is_capture(args.input) else "log"
    if args.input_kind == "capture":
        if args.capture:
            parser.error("--capture is only used when the main input is a .log file")
        args.pcap = args.input
    else:
        args.pcap = args.capture
        if args.pcap and not args.pcap.is_file():
            parser.error(f"companion capture not found: {args.pcap}")
        if args.pcap and not is_capture(args.pcap):
            parser.error(f"--capture is not a PCAP/PCAPNG file: {args.pcap}")
        if args.pcap and not args.tls_keylog and is_tls_keylog(args.input):
            args.tls_keylog = args.input
    if args.pcap and shutil.which("tshark") is None:
        parser.error("PCAP analysis requires tshark")
    for label, path in (("TLS key log", args.tls_keylog), ("RSA key", args.tls_rsa_key)):
        if path and not path.is_file():
            parser.error(f"{label} not found: {path}")
    if args.display_filter and not args.pcap:
        parser.error("--filter requires a PCAP/PCAPNG input or --capture")
    if not args.pcap and any((args.export_dir, args.write_filtered, args.embed_secrets, args.tls_rsa_key)):
        parser.error("capture-specific output/decryption options require a PCAP/PCAPNG input or --capture")
    if args.write_filtered and not args.display_filter:
        parser.error("--write-filtered requires --filter")
    if args.embed_secrets and not args.tls_keylog:
        parser.error("--embed-secrets requires --tls-keylog")
    if args.tls_rsa_port < 0 or args.tls_rsa_port > 65535:
        parser.error("--tls-rsa-port must be between 0 and 65535")


def command_version(executable: str) -> str:
    path = shutil.which(executable)
    if not path:
        return "unavailable"
    result = subprocess.run([path, "--version"], capture_output=True, text=True, errors="replace", check=False)
    return result.stdout.splitlines()[0].strip() if result.stdout else "unknown"


def capture_info(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "format": path.suffix.lower().lstrip(".") or "capture",
    }
    if shutil.which("capinfos") is None:
        info["capinfos"] = "unavailable"
        return info
    result = subprocess.run(
        ["capinfos", "-M", str(path)],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "capinfos rejected the capture")
    wanted = {
        "File type": "format",
        "File encapsulation": "encapsulation",
        "Number of packets": "packets",
        "Capture duration": "duration",
        "First packet time": "first_packet",
        "Last packet time": "last_packet",
        "Data size": "data_size",
        "Average data rate": "average_rate",
        "SHA256": "capinfos_sha256",
        "Strict time order": "strict_time_order",
    }
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        name, value = (part.strip() for part in line.split(":", 1))
        if name in wanted:
            info[wanted[name]] = value
    return info


def capture_comments(runner: Tshark, path: Path) -> tuple[list[dict[str, Any]], list[tuple[str, bytes]]]:
    comments: list[dict[str, Any]] = []
    blobs: list[tuple[str, bytes]] = []
    result = subprocess.run(
        ["capinfos", "-M", "-k", str(path)], capture_output=True, text=True,
        errors="replace", check=False,
    ) if shutil.which("capinfos") else subprocess.CompletedProcess([], 0, "", "")
    active = False
    capture_lines: list[str] = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("capture comment"):
            active = True
            value = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
            if value and value != "(none)":
                capture_lines.append(value)
            continue
        if active and (line.startswith(" ") or line.startswith("\t")):
            if stripped:
                capture_lines.append(stripped)
            continue
        active = False
    if capture_lines:
        value = "\n".join(capture_lines)
        comments.append({"scope": "capture", "value": safe_text(value, 2000)})
        blobs.append(("PCAPNG capture comment", value.encode()))
    try:
        rows = runner.fields(("frame.number", "frame.comment"))
    except RuntimeError:
        rows = []
    for frame, value in rows:
        if not value:
            continue
        comments.append({"scope": "packet", "frame": frame, "value": safe_text(value, 2000)})
        blobs.append((f"PCAPNG packet comment frame {frame}", value.encode()))
    return comments, blobs


def analyze_log_file(path: Path, top: int) -> tuple[dict[str, Any], list[Finding], list[tuple[str, bytes]]]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        raw = handle.read(MAX_RAW_SCAN_BYTES)
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    ip_counts = Counter(re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text))
    url_counts = Counter(re.findall(r"https?://[^\s\"'<>]+", text, re.IGNORECASE))
    domain_counts = Counter(re.findall(r"(?i)(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,63}(?![\w.-])", text))
    level_counts = Counter(match.upper() for match in re.findall(r"(?i)\b(?:trace|debug|info|notice|warn(?:ing)?|error|critical|fatal)\b", text))
    secret_counts: Counter[str] = Counter()
    valid_secret_lines = 0
    malformed_secret_lines = 0
    json_lines = 0
    timestamped_lines = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("{"):
            try:
                json.loads(stripped)
                json_lines += 1
            except json.JSONDecodeError:
                pass
        if re.match(r"^(?:\d{4}-\d{2}-\d{2}[T ]|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", stripped):
            timestamped_lines += 1
        fields = stripped.split()
        if fields and fields[0] in TLS_SECRET_LABELS:
            secret_counts[fields[0]] += 1
            valid_hex = len(fields) == 3 and all(re.fullmatch(r"[0-9a-fA-F]+", value) for value in fields[1:])
            valid_lengths = valid_hex and len(fields[1]) == 64 and len(fields[2]) >= 32 and len(fields[2]) % 2 == 0
            if valid_lengths:
                valid_secret_lines += 1
            else:
                malformed_secret_lines += 1
    nonempty = sum(bool(line.strip()) for line in lines)
    kind = "TLS key log" if valid_secret_lines else "text log"
    if json_lines and json_lines >= max(1, nonempty // 2):
        kind = "JSON Lines log"
    elif timestamped_lines and timestamped_lines >= max(1, nonempty // 2):
        kind = "timestamped text log"
    info: dict[str, Any] = {
        "kind": kind,
        "lines": len(lines),
        "nonempty_lines": nonempty,
        "bytes_scanned": len(raw),
        "truncated": size > len(raw),
        "top_ips": dict(ip_counts.most_common(top)),
        "top_domains": dict(domain_counts.most_common(top)),
        "top_urls": dict(url_counts.most_common(top)),
        "levels": dict(level_counts.most_common()),
        "tls_secret_labels": dict(secret_counts.most_common()),
        "valid_tls_secret_lines": valid_secret_lines,
        "malformed_tls_secret_lines": malformed_secret_lines,
    }
    findings: list[Finding] = []
    if malformed_secret_lines:
        findings.append(Finding("medium", "LOG", "Malformed TLS key-log entries", f"{malformed_secret_lines} malformed line(s)"))
    if secret_counts and not valid_secret_lines:
        findings.append(Finding("high", "LOG", "TLS key log is unusable", "recognized labels exist but no valid three-field secret line was found"))
    if level_counts.get("ERROR", 0) or level_counts.get("CRITICAL", 0) or level_counts.get("FATAL", 0):
        total = level_counts.get("ERROR", 0) + level_counts.get("CRITICAL", 0) + level_counts.get("FATAL", 0)
        findings.append(Finding("info", "LOG", "Error-level events", f"{total} error/critical/fatal token(s)"))
    blobs = [(f"log file {path.name}", raw)]
    for number, line in enumerate(lines, start=1):
        if len(line) <= MAX_BLOB_BYTES and ("base64," in line.lower() or "0x" in line or "flag" in line.lower()):
            blobs.append((f"log line {number}", line.encode()))
    return info, findings, blobs


def build_inventory(runner: Tshark, top: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[Flow], dict[str, list[float]]]:
    fields = (
        "frame.time_epoch", "frame.len", "frame.protocols", "eth.src", "eth.dst",
        "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport",
        "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.len",
    )
    protocols: Counter[str] = Counter()
    hosts: dict[str, dict[str, int]] = defaultdict(lambda: {"sent_packets": 0, "received_packets": 0, "sent_bytes": 0, "received_bytes": 0})
    flows: dict[tuple[str, str, str], Flow] = {}
    directed_times: dict[str, list[float]] = defaultdict(list)

    for row in runner.fields(fields):
        timestamp = parse_number(row[0])
        length = int(parse_number(row[1]))
        for protocol in filter(None, row[2].split(":")):
            protocols[protocol] += 1
        source = row[5] or row[7] or row[3]
        destination = row[6] or row[8] or row[4]
        if not source or not destination:
            continue
        hosts[source]["sent_packets"] += 1
        hosts[source]["sent_bytes"] += length
        hosts[destination]["received_packets"] += 1
        hosts[destination]["received_bytes"] += length
        if row[9] or row[10]:
            protocol = "TCP"
            source_endpoint = f"{source}:{row[9] or '?'}"
            destination_endpoint = f"{destination}:{row[10] or '?'}"
        elif row[11] or row[12]:
            protocol = "UDP"
            source_endpoint = f"{source}:{row[11] or '?'}"
            destination_endpoint = f"{destination}:{row[12] or '?'}"
        else:
            protocol = "IP"
            source_endpoint, destination_endpoint = source, destination
        ordered = sorted((source_endpoint, destination_endpoint))
        key = (protocol, ordered[0], ordered[1])
        flow = flows.get(key)
        if flow is None:
            flow = Flow(protocol, ordered[0], ordered[1], first=timestamp, last=timestamp)
            flows[key] = flow
        flow.packets += 1
        flow.bytes += length
        flow.first = min(flow.first, timestamp)
        flow.last = max(flow.last, timestamp)
        if row[13] and int(parse_number(row[13])) > 0:
            flow.timestamps.append(timestamp)
            directed_times[f"{protocol} {source_endpoint} → {destination_endpoint}"].append(timestamp)

    protocol_rows = [{"protocol": name, "packets": count} for name, count in protocols.most_common(top)]
    host_rows = []
    for address, values in hosts.items():
        total_packets = values["sent_packets"] + values["received_packets"]
        total_bytes = values["sent_bytes"] + values["received_bytes"]
        host_rows.append({"address": address, **values, "packets": total_packets, "bytes": total_bytes})
    host_rows.sort(key=lambda item: (item["bytes"], item["packets"]), reverse=True)
    flow_rows = sorted(flows.values(), key=lambda flow: (flow.bytes, flow.packets), reverse=True)
    return protocol_rows, host_rows[:top], flow_rows[:top], directed_times


def dns_inventory(runner: Tshark, top: int) -> tuple[list[dict[str, Any]], list[Finding], list[tuple[str, bytes]]]:
    fields = ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "dns.flags.response", "dns.flags.rcode", "dns.qry.type", "dns.qry.name", "dns.a", "dns.aaaa", "dns.cname")
    rows = runner.fields(fields, "dns")
    query_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    nxdomain = 0
    suspicious: list[Finding] = []
    dns_blobs: list[tuple[str, bytes]] = []
    tunnel_fragments: dict[str, list[tuple[float, int | None, str]]] = defaultdict(list)
    for row in rows:
        source = row[2] or row[3]
        query = row[9].rstrip(".")
        is_response = row[6] in {"1", "True", "true"}
        if row[7] == "3":
            nxdomain += 1
        if not query or is_response:
            continue
        query_counts[query] += 1
        source_counts[source] += 1
        type_counts[row[8] or "unknown"] += 1
        dns_blobs.append((f"DNS frame {row[0]}", query.encode()))
        labels = query.split(".")
        longest = max(labels, key=len)
        entropy = shannon_entropy(longest)
        reasons = []
        if len(query) > 80:
            reasons.append(f"name length {len(query)}")
        if len(longest) >= 24 and entropy >= 3.5:
            reasons.append(f"label entropy {entropy:.2f}")
        if row[8] in {"10", "16"}:
            reasons.append(f"query type {row[8]}")
        if reasons:
            suspicious.append(Finding("medium", "DNS", "Possible DNS tunneling", f"frame {row[0]}, {source}, {query}: {', '.join(reasons)}"))
        if len(labels) >= 3:
            parent = ".".join(labels[-2:]).lower()
            data_labels = labels[:-2]
            sequence: int | None = None
            if data_labels and data_labels[0].isdigit():
                sequence = int(data_labels.pop(0))
            elif data_labels:
                numbered = re.fullmatch(r"(\d+)[_-](.+)", data_labels[0])
                if numbered:
                    sequence = int(numbered.group(1))
                    data_labels[0] = numbered.group(2)
            fragment = "".join(data_labels)
            if fragment and re.fullmatch(r"(?i)[a-z0-9_+/=-]+", fragment):
                tunnel_fragments[parent].append((parse_number(row[1]), sequence, fragment))
    if nxdomain:
        suspicious.append(Finding("info", "DNS", "NXDOMAIN responses", f"{nxdomain} response(s) with rcode 3"))
    inventory = [
        {"query": name, "count": count}
        for name, count in query_counts.most_common(top)
    ]
    if source_counts:
        inventory.append({"top_sources": dict(source_counts.most_common(top))})
    if type_counts:
        inventory.append({"query_types": dict(type_counts.most_common())})
    for parent, fragments in tunnel_fragments.items():
        if len(fragments) < 2:
            continue
        ordered = sorted(
            fragments,
            key=lambda item: (
                item[1] is None,
                item[1] if item[1] is not None else item[0],
            ),
        )
        unique_fragments = list(dict.fromkeys(fragment for _, _, fragment in ordered))
        if len(unique_fragments) >= 2:
            joined = "".join(unique_fragments).encode()
            dns_blobs.append((f"reassembled DNS fragments for {parent}", joined))
    return inventory, suspicious[: max(top, 30)], dns_blobs


def http_inventory(runner: Tshark, top: int) -> list[dict[str, Any]]:
    fields = ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "http.request.method", "http.host", "http.request.uri", "http.response.code", "http.content_type", "http.content_length", "http.user_agent")
    rows = runner.fields(fields)
    output = []
    for row in rows:
        if not (row[6] or row[9]):
            continue
        output.append({
            "frame": row[0], "time": row[1], "source": row[2] or row[3],
            "destination": row[4] or row[5], "method": row[6], "host": row[7],
            "uri": row[8], "status": row[9], "content_type": row[10],
            "content_length": row[11], "user_agent": row[12],
        })
        if len(output) >= max(top * 4, top):
            break
    return output


def tls_inventory(runner: Tshark, top: int) -> tuple[list[dict[str, Any]], list[Finding]]:
    fields = ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.dstport", "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str", "tls.handshake.ciphersuite", "tls.handshake.ja3", "tls.handshake.ja4")
    rows = runner.fields(fields)
    output: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for row in rows:
        if row[7] not in {"1", "2"}:
            continue
        entry = {
            "frame": row[0], "time": row[1], "source": row[2] or row[3],
            "destination": row[4] or row[5], "port": row[6], "handshake": row[7],
            "sni": row[8], "alpn": row[9], "cipher": row[10], "ja3": row[11], "ja4": row[12],
        }
        output.append(entry)
        if row[7] == "1" and not row[8]:
            findings.append(Finding("info", "TLS", "ClientHello without SNI", f"frame {row[0]}: {entry['source']} → {entry['destination']}:{row[6]}"))
        if row[6] and row[6] != "443":
            findings.append(Finding("info", "TLS", "TLS on a non-standard port", f"frame {row[0]}: destination port {row[6]}"))
        lowered_cipher = row[10].lower()
        if any(value in lowered_cipher for value in ("0x0004", "0x0005", "0x04", "0x05")):
            findings.append(Finding("high", "TLS", "RC4 TLS cipher suite", f"frame {row[0]}: cipher {row[10]}"))
        if len(output) >= max(top * 4, top):
            break
    return output, findings


def hostname_inventory(runner: Tshark, top: int) -> list[dict[str, Any]]:
    fields = ("frame.number", "ip.src", "ipv6.src", "dhcp.option.hostname", "nbns.name")
    rows = runner.fields(fields)
    output = []
    for row in rows:
        names = [value for value in row[3:] if value]
        if not names:
            continue
        output.append({"frame": row[0], "source": row[1] or row[2], "names": names})
        if len(output) >= max(top * 3, top):
            break
    return output


def operational_findings(runner: Tshark, directed_times: dict[str, list[float]], top: int) -> list[Finding]:
    findings: list[Finding] = []
    checks = (
        ("medium", "TCP", "TCP resets", "tcp.flags.reset == 1"),
        ("medium", "TCP", "TCP retransmissions", "tcp.analysis.retransmission"),
        ("info", "DNS", "DNS errors", "dns.flags.response == 1 && dns.flags.rcode != 0"),
        ("medium", "TLS", "Non-TLS payload on port 443", "tcp.port == 443 && tcp.len > 0 && !tls"),
    )
    for severity, category, summary, display_filter in checks:
        count = runner.count(display_filter)
        if count:
            findings.append(Finding(severity, category, summary, f"{count} matching packet(s)"))

    syn_rows = runner.fields(("ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.dstport"), "tcp.flags.syn == 1 && tcp.flags.ack == 0")
    scan_map: dict[str, set[str]] = defaultdict(set)
    for row in syn_rows:
        source = row[0] or row[1]
        destination = row[2] or row[3]
        if source and destination:
            scan_map[source].add(f"{destination}:{row[4]}")
    for source, targets in scan_map.items():
        if len(targets) >= 15:
            findings.append(Finding("high", "Scan", "Possible SYN scan", f"{source} contacted {len(targets)} unique destination/port pairs"))

    periodic = []
    for flow, timestamps in directed_times.items():
        if len(timestamps) < 5:
            continue
        ordered = sorted(set(timestamps))
        intervals = [right - left for left, right in zip(ordered, ordered[1:]) if right > left]
        if len(intervals) < 4:
            continue
        mean = statistics.fmean(intervals)
        if mean <= 0.5:
            continue
        deviation = statistics.pstdev(intervals)
        coefficient = deviation / mean if mean else 1.0
        if coefficient <= 0.15:
            periodic.append((coefficient, flow, mean, len(ordered)))
    for coefficient, flow, mean, count in sorted(periodic)[:top]:
        findings.append(Finding("medium", "C2", "Periodic payload traffic", f"{flow}; {count} events, mean {mean:.2f}s, CV {coefficient:.3f}"))
    return findings


def readable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    readable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in data)
    return readable / len(data)


def plaintext_score(data: bytes) -> float:
    """Return a conservative 0..1 score for human-readable protocol text."""
    if not data:
        return 0.0
    sample = data[:4096]
    readable = readable_ratio(sample)
    text_like = sum(
        byte in b" \t\r\n.,;:!?'-_{}[]()/" or 48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122
        for byte in sample
    ) / len(sample)
    return 0.65 * readable + 0.35 * text_like


def tcp_stream_inventory(
    runner: Tshark,
    top: int,
) -> tuple[list[dict[str, Any]], list[PayloadPacket], list[tuple[str, bytes]]]:
    """Build direction-aware TCP transcripts and reusable reassembled blobs."""
    fields = (
        "frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ipv6.src",
        "tcp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport", "tcp.seq_raw", "tcp.payload",
    )
    packets: list[PayloadPacket] = []
    for row in runner.fields(fields, "tcp.payload"):
        payload = parse_hex_bytes(row[10])
        if not payload or not row[2]:
            continue
        source_address = row[3] or row[4]
        destination_address = row[6] or row[7]
        packets.append(PayloadPacket(
            frame=int(parse_number(row[0])),
            timestamp=parse_number(row[1]),
            stream=int(parse_number(row[2])),
            source=f"{source_address}:{row[5] or '?'}",
            destination=f"{destination_address}:{row[8] or '?'}",
            sequence=int(parse_number(row[9])),
            payload=payload,
        ))

    grouped: dict[int, list[PayloadPacket]] = defaultdict(list)
    for packet in packets:
        grouped[packet.stream].append(packet)
    streams: list[dict[str, Any]] = []
    blobs: list[tuple[str, bytes]] = []
    for stream_id, entries in grouped.items():
        directions: dict[tuple[str, str], list[PayloadPacket]] = defaultdict(list)
        for packet in entries:
            directions[(packet.source, packet.destination)].append(packet)
        direction_rows: list[dict[str, Any]] = []
        for (source, destination), direction_packets in directions.items():
            chunks = reassemble_tcp_segments([
                (packet.sequence, packet.frame, packet.payload) for packet in direction_packets
            ])
            reassembled = b"".join(chunks)[:MAX_BLOB_BYTES]
            frames = sorted(packet.frame for packet in direction_packets)
            label = f"TCP stream {stream_id} {source} -> {destination} sequence reassembly"
            if reassembled:
                blobs.append((label, reassembled))
            direction_rows.append({
                "source": source,
                "destination": destination,
                "frames": frames,
                "packets": len(direction_packets),
                "wire_bytes": sum(len(packet.payload) for packet in direction_packets),
                "reassembled_bytes": len(reassembled),
                "preview": safe_text(reassembled, 320),
                "hex_preview": reassembled[:64].hex(),
            })
        streams.append({
            "stream": stream_id,
            "endpoints": sorted({packet.source for packet in entries} | {packet.destination for packet in entries}),
            "payload_packets": len(entries),
            "payload_bytes": sum(len(packet.payload) for packet in entries),
            "first_frame": min(packet.frame for packet in entries),
            "last_frame": max(packet.frame for packet in entries),
            "directions": sorted(direction_rows, key=lambda item: (item["source"], item["destination"])),
        })
    streams.sort(key=lambda item: (item["payload_bytes"], item["payload_packets"]), reverse=True)
    return streams[: max(top, 1)], packets, blobs


def detect_repeating_xor(
    packets: Sequence[PayloadPacket],
    top: int,
) -> tuple[list[dict[str, Any]], list[tuple[str, bytes]]]:
    """Validate XOR challenge/response keys against other payloads in each stream."""
    by_stream: dict[int, list[PayloadPacket]] = defaultdict(list)
    for packet in packets:
        by_stream[packet.stream].append(packet)
    findings: list[dict[str, Any]] = []
    decrypted_blobs: list[tuple[str, bytes]] = []
    seen: set[tuple[int, bytes, int]] = set()
    flag_regex = compile_flag_regex(None)
    for stream_id, stream_packets in by_stream.items():
        ordered = sorted(stream_packets, key=lambda packet: (packet.frame, packet.timestamp))[:300]
        small = [packet for packet in ordered if 4 <= len(packet.payload) <= 64]
        for left_index, left in enumerate(small):
            for right in small[left_index + 1:]:
                if left.source == right.source or len(left.payload) != len(right.payload):
                    continue
                if right.frame - left.frame > 40:
                    break
                key = minimal_period(bytes(a ^ b for a, b in zip(left.payload, right.payload)))
                if not key or len(key) > 32 or not any(key):
                    continue
                best: tuple[float, float, PayloadPacket, bytes] | None = None
                for target in ordered:
                    if target.frame in {left.frame, right.frame} or len(target.payload) < max(16, len(key) * 2):
                        continue
                    plaintext = repeating_xor(target.payload, key)
                    score = plaintext_score(plaintext)
                    gain = score - plaintext_score(target.payload)
                    flag_like = bool(flag_regex.search(plaintext))
                    if score < 0.78 or (gain < 0.12 and not flag_like):
                        continue
                    candidate = (score, gain, target, plaintext)
                    if best is None:
                        best = candidate
                    elif candidate[:2] > best[:2]:
                        best = candidate
                if best is None:
                    continue
                score, gain, target, plaintext = best
                identity = (stream_id, key, target.frame)
                if identity in seen:
                    continue
                seen.add(identity)
                source = (
                    f"auto-XOR TCP stream {stream_id}, key from frames {left.frame}/{right.frame}, "
                    f"decrypted frame {target.frame}"
                )
                decrypted_blobs.append((source, plaintext))
                findings.append({
                    "stream": stream_id,
                    "key_hex": key.hex(),
                    "key_bytes": len(key),
                    "known_frames": [left.frame, right.frame],
                    "known_directions": [f"{left.source} -> {left.destination}", f"{right.source} -> {right.destination}"],
                    "target_frame": target.frame,
                    "target_direction": f"{target.source} -> {target.destination}",
                    "confidence": round(score, 3),
                    "score_gain": round(gain, 3),
                    "plaintext_preview": safe_text(plaintext, 600),
                    "plaintext_hex_preview": plaintext[:64].hex(),
                })
    findings.sort(key=lambda item: (item["confidence"], item["score_gain"]), reverse=True)
    return findings[: max(top, 1)], decrypted_blobs[: max(top, 1)]


def xor_blob_variants(blobs: Iterable[tuple[str, bytes]], key: bytes) -> list[tuple[str, bytes]]:
    return [(f"{source}, repeating XOR key {key.hex()}", repeating_xor(data, key)) for source, data in blobs]


def covert_channel_candidates(runner: Tshark, top: int) -> tuple[list[dict[str, Any]], list[Finding], list[tuple[str, bytes]]]:
    fields = (
        "frame.number", "frame.time_epoch", "eth.type", "eth.dst", "ip.id",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len",
        "tcp.flags", "tcp.len", "tcp.payload", "udp.length", "udp.payload",
        "tcp.stream", "udp.stream", "ip.src", "ipv6.src", "tcp.srcport", "udp.srcport",
    )
    rows = runner.fields(fields)
    ethertypes: Counter[str] = Counter()
    typed_macs: dict[str, list[tuple[int, str]]] = defaultdict(list)
    single_tcp: dict[str, list[tuple[int, float, bytes]]] = defaultdict(list)
    single_udp: dict[str, list[tuple[int, float, bytes]]] = defaultdict(list)
    headers: dict[str, bytearray] = defaultdict(bytearray)
    for row in rows:
        frame = int(parse_number(row[0]))
        timestamp = parse_number(row[1])
        if row[2]:
            ethertypes[row[2]] += 1
            if row[3]:
                typed_macs[row[2]].append((frame, row[3]))
        values = {
            "IP ID low byte": row[4],
            "TCP source-port low byte": row[5],
            "TCP destination-port low byte": row[6],
            "UDP source-port low byte": row[7],
            "UDP destination-port low byte": row[8],
            "frame-length low byte": row[9],
            "TCP flags low byte": row[10],
        }
        for name, value in values.items():
            if not value:
                continue
            try:
                number = int(value, 0)
            except ValueError:
                number = int(parse_number(value))
            headers[name].append(number & 0xFF)
        tcp_payload = parse_hex_bytes(row[12])
        if int(parse_number(row[11])) == 1 and len(tcp_payload) == 1:
            key = f"TCP stream {row[15]} from {row[17] or row[18]}:{row[19]} one-byte payloads"
            single_tcp[key].append((frame, timestamp, tcp_payload))
        udp_payload = parse_hex_bytes(row[14])
        if len(udp_payload) == 1:
            key = f"UDP stream {row[16]} from {row[17] or row[18]}:{row[20]} one-byte payloads"
            single_udp[key].append((frame, timestamp, udp_payload))
    candidates: list[dict[str, Any]] = []
    findings: list[Finding] = []
    blobs: list[tuple[str, bytes]] = []
    for ethertype, count in ethertypes.most_common():
        unusual = ethertype.lower() in {"0xffff", "ffff"} or count <= max(4, len(rows) // 100)
        if not unusual or count < 4:
            continue
        mac_bytes = bytearray()
        for _, mac in sorted(typed_macs[ethertype]):
            try:
                mac_bytes.append(int(mac.split(":", 1)[0], 16))
            except (ValueError, IndexError):
                continue
        data = bytes(mac_bytes)
        source = f"first destination-MAC octet where EtherType={ethertype}, frame order"
        if data:
            blobs.append((source, data))
            candidates.append({"source": source, "bytes": len(data), "preview": safe_text(data), "readable_ratio": round(readable_ratio(data), 3)})
            findings.append(Finding("medium", "Covert", "Unusual EtherType carries changing MAC bytes", f"{ethertype}: {count} frame(s); first destination-MAC octets were reconstructed"))
    for groups in (single_tcp, single_udp):
        for name, entries in groups.items():
            if len(entries) < 4:
                continue
            for order_name, position in (("frame", 0), ("timestamp", 1)):
                data = b"".join(item[2] for item in sorted(entries, key=lambda item: (item[position], item[0])))[:MAX_BLOB_BYTES]
                source = f"{name}, {order_name} order"
                blobs.append((source, data))
                candidates.append({"source": source, "bytes": len(data), "preview": safe_text(data), "readable_ratio": round(readable_ratio(data), 3)})
    for name, data_value in headers.items():
        data = bytes(data_value[:MAX_BLOB_BYTES])
        if len(data) < 8 or readable_ratio(data) < 0.7:
            continue
        source = f"{name}, frame order"
        blobs.append((source, data))
        candidates.append({"source": source, "bytes": len(data), "preview": safe_text(data), "readable_ratio": round(readable_ratio(data), 3)})
    candidates.sort(key=lambda item: (item["readable_ratio"], item["bytes"]), reverse=True)
    return candidates[: max(top * 2, top)], findings, blobs


def raw_chunks(path: Path, chunk_size: int = 4 * 1024 * 1024) -> Iterable[tuple[str, bytes]]:
    remaining = MAX_RAW_SCAN_BYTES
    offset = 0
    overlap = b""
    with path.open("rb") as handle:
        while remaining > 0:
            chunk = handle.read(min(chunk_size, remaining))
            if not chunk:
                break
            yield f"capture raw bytes @ {offset}", overlap + chunk
            overlap = chunk[-1024:]
            offset += len(chunk)
            remaining -= len(chunk)


def reassemble_tcp_segments(segments: list[tuple[int, int, bytes]]) -> list[bytes]:
    if not segments:
        return []
    ordered = sorted(segments, key=lambda item: (item[0], item[1], -len(item[2])))
    chunks: list[bytearray] = []
    expected: int | None = None
    for sequence, _, payload in ordered:
        if expected is None or sequence > expected:
            chunks.append(bytearray(payload))
            expected = sequence + len(payload)
            continue
        overlap = expected - sequence
        if overlap < len(payload):
            chunks[-1].extend(payload[overlap:])
            expected += len(payload) - overlap
    return [bytes(chunk[:MAX_BLOB_BYTES]) for chunk in chunks if chunk]


def payload_blobs(runner: Tshark) -> list[tuple[str, bytes]]:
    fields = (
        "frame.number", "frame.time_epoch", "tcp.stream", "udp.stream", "ip.src",
        "ipv6.src", "tcp.srcport", "udp.srcport", "tcp.seq_raw", "tcp.payload",
        "udp.payload", "tcp.reassembled.data", "http.file_data", "http2.data.data",
        "mime_multipart.part", "data.data",
    )
    # Avoid a filter made of optional dissector fields: older TShark releases
    # may not know one of them, which would otherwise abort the whole pass.
    rows = runner.fields(fields)
    blobs: list[tuple[str, bytes]] = []
    tcp_segments: dict[str, list[tuple[int, int, bytes]]] = defaultdict(list)
    tcp_frame_order: dict[str, list[tuple[int, float, bytes]]] = defaultdict(list)
    udp_order: dict[str, list[tuple[int, float, bytes]]] = defaultdict(list)
    for row in rows:
        frame = int(parse_number(row[0]))
        timestamp = parse_number(row[1])
        source = row[4] or row[5]
        tcp_key = f"TCP stream {row[2]} from {source}:{row[6]}"
        udp_key = f"UDP stream {row[3]} from {source}:{row[7]}"
        tcp_payload = parse_hex_bytes(row[9])
        udp_payload = parse_hex_bytes(row[10])
        if tcp_payload:
            sequence = int(parse_number(row[8]))
            tcp_segments[tcp_key].append((sequence, frame, tcp_payload))
            tcp_frame_order[tcp_key].append((frame, timestamp, tcp_payload))
        if udp_payload:
            udp_order[udp_key].append((frame, timestamp, udp_payload))
        for index, value in enumerate(row[11:], start=11):
            decoded = parse_hex_bytes(value)
            if decoded:
                blobs.append((f"frame {row[0]} decoded field {fields[index]}", decoded[:MAX_BLOB_BYTES]))
    for key, segments in tcp_segments.items():
        for part, data in enumerate(reassemble_tcp_segments(segments), start=1):
            blobs.append((f"{key}, TCP sequence reassembly part {part}", data))
    for key, entries in tcp_frame_order.items():
        for order_name, position in (("frame", 0), ("timestamp", 1)):
            data = b"".join(item[2] for item in sorted(entries, key=lambda item: (item[position], item[0])))[:MAX_BLOB_BYTES]
            if data:
                blobs.append((f"{key}, {order_name} order", data))
    for key, entries in udp_order.items():
        for order_name, position in (("frame", 0), ("timestamp", 1)):
            data = b"".join(item[2] for item in sorted(entries, key=lambda item: (item[position], item[0])))[:MAX_BLOB_BYTES]
            if data:
                blobs.append((f"{key}, {order_name} order", data))
    return blobs


def one_layer_decodings(data: bytes) -> Iterable[tuple[str, bytes]]:
    if b"%" in data:
        decoded = urllib.parse.unquote_to_bytes(data.decode("latin1", errors="ignore"))
        if decoded != data:
            yield "url", decoded
    for token in re.findall(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])", data[:MAX_BLOB_BYTES]):
        if len(token) > 65536:
            continue
        try:
            decoded = base64.b64decode(token + b"=" * ((4 - len(token) % 4) % 4), validate=False)
        except (ValueError, binascii.Error):
            continue
        if decoded:
            yield "base64", decoded
    for token in re.findall(rb"(?i)(?<![0-9a-f])[0-9a-f]{16,}(?![0-9a-f])", data[:MAX_BLOB_BYTES]):
        if len(token) % 2 or len(token) > 131072:
            continue
        try:
            yield "hex", bytes.fromhex(token.decode())
        except ValueError:
            pass
    tokens = re.findall(rb"(?i)(?:0x[0-9a-f]{2}[\s,;:_-]*){2,}", data[:MAX_BLOB_BYTES])
    for token in tokens:
        decoded = bytes(int(value, 16) for value in re.findall(rb"(?i)0x([0-9a-f]{2})", token))
        if decoded:
            yield "0x-bytes", decoded
    for token in re.findall(rb"(?i)(?<![a-z2-7])[a-z2-7]{16,}(?![a-z2-7])", data[:MAX_BLOB_BYTES]):
        if len(token) > 65536:
            continue
        try:
            decoded = base64.b32decode(token.upper() + b"=" * ((8 - len(token) % 8) % 8))
        except (ValueError, binascii.Error):
            continue
        if decoded:
            yield "base32", decoded
    for name, window_bits in (("zlib", zlib.MAX_WBITS), ("gzip", 16 + zlib.MAX_WBITS)):
        try:
            decompressor = zlib.decompressobj(window_bits)
            decoded = decompressor.decompress(data, MAX_BLOB_BYTES + 1)
        except zlib.error:
            continue
        if decoded and len(decoded) <= MAX_BLOB_BYTES:
            yield name, decoded


def decoded_variants(data: bytes, max_depth: int = 3) -> Iterable[tuple[str, bytes]]:
    queue: list[tuple[str, bytes, int]] = [("plain", data[:MAX_BLOB_BYTES], 0)]
    seen: set[bytes] = set()
    while queue:
        encoding, candidate, depth = queue.pop(0)
        fingerprint = hashlib.sha256(candidate).digest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        yield encoding, candidate
        if depth >= max_depth:
            continue
        for child_encoding, decoded in one_layer_decodings(candidate):
            if decoded and len(decoded) <= MAX_BLOB_BYTES:
                chain = child_encoding if encoding == "plain" else f"{encoding}→{child_encoding}"
                queue.append((chain, decoded, depth + 1))


def compile_flag_regex(prefix: str | Sequence[str] | None) -> re.Pattern[bytes]:
    prefixes = [prefix] if isinstance(prefix, str) else list(prefix or [])
    bases = [re.escape((item[:-1] if item.endswith("{") else item).encode()) for item in prefixes if item]
    if bases:
        base = b"(?:" + b"|".join(bases) + b")"
    else:
        base = rb"(?:flag|ctf|HTB|THM|picoCTF|DUCTF|uiuctf)"
    return re.compile(base + rb"(?:\{[^}\r\n]{1,512}\}|\[[^\]\r\n]{1,512}\]|[:=_-][A-Za-z0-9_./+\-=]{4,512})", re.IGNORECASE)


def scan_matches(
    blobs: Iterable[tuple[str, bytes]],
    *,
    flag_prefix: str | Sequence[str] | None,
    patterns: Sequence[str],
    rc4_key: bytes | None,
    rc4_drop: int,
) -> list[Match]:
    flag_regex = compile_flag_regex(flag_prefix)
    compiled_patterns = []
    for pattern in patterns:
        try:
            compiled_patterns.append((pattern, re.compile(pattern, re.IGNORECASE)))
        except re.error as error:
            raise ValueError(f"invalid pattern {pattern!r}: {error}") from error
    matches: list[Match] = []
    seen: set[tuple[str, str, str]] = set()
    for source, original in blobs:
        candidates = list(decoded_variants(original[:MAX_BLOB_BYTES]))
        if rc4_key:
            candidates.append(("rc4", rc4(original[:MAX_BLOB_BYTES], rc4_key, rc4_drop)))
        for encoding, data in candidates:
            for found in flag_regex.finditer(data):
                value = safe_text(found.group())
                key = ("flag", value, source)
                if key not in seen:
                    seen.add(key)
                    matches.append(Match("flag", value, source, encoding))
            text = data.decode("utf-8", errors="replace")
            for pattern_name, pattern in compiled_patterns:
                for found in pattern.finditer(text):
                    value = safe_text(found.group())
                    key = (pattern_name, value, source)
                    if key not in seen:
                        seen.add(key)
                        matches.append(Match(f"pattern:{pattern_name}", value, source, encoding))
            if len(matches) >= 500:
                return matches
    return matches



def default_artifact_root(input_path: Path) -> Path:
    """Return a non-destructive per-run artifact directory next to the input."""
    base = input_path.parent / f"{input_path.stem}_picup"
    if not base.exists() or (base.is_dir() and not any(base.iterdir())):
        return base
    index = 2
    while True:
        candidate = input_path.parent / f"{input_path.stem}_picup_{index}"
        if not candidate.exists() or (candidate.is_dir() and not any(candidate.iterdir())):
            return candidate
        index += 1


def configure_automatic_actions(args: argparse.Namespace) -> None:
    """Enable artifact carving on every run and the optional --all extras."""
    root = args.output_dir if args.output_dir else default_artifact_root(args.input)
    args.artifact_root = root
    if args.extract_images is None:
        args.extract_images = root / "images"
    if args.extract_files is None:
        args.extract_files = root / "files"
    if args.all and args.pcap and args.export_dir is None:
        args.export_dir = root / "objects"
    if args.all and args.pcap and args.timeline_format == "none":
        args.timeline_format = "both"


def file_chunks(path: Path, *, label: str, chunk_size: int = 4 * 1024 * 1024) -> Iterable[tuple[str, bytes]]:
    """Yield bounded overlapping chunks so carving is attempted across the whole input window."""
    remaining = MAX_RAW_SCAN_BYTES
    offset = 0
    overlap = b""
    with path.open("rb") as handle:
        while remaining > 0:
            chunk = handle.read(min(chunk_size, remaining))
            if not chunk:
                break
            yield f"{label} @ {offset}", overlap + chunk
            overlap = chunk[-4096:]
            offset += len(chunk)
            remaining -= len(chunk)


def describe_file(path: Path) -> tuple[str, str]:
    """Best-effort MIME and human-readable type without making `file(1)` mandatory."""
    mime = "application/octet-stream"
    description = "data"
    file_tool = shutil.which("file")
    if not file_tool:
        return mime, description
    result = subprocess.run([file_tool, "-b", "--mime-type", str(path)], capture_output=True, text=True, errors="replace", check=False)
    if result.stdout.strip():
        mime = result.stdout.strip()
    result = subprocess.run([file_tool, "-b", str(path)], capture_output=True, text=True, errors="replace", check=False)
    if result.stdout.strip():
        description = result.stdout.strip()
    return mime, description


def _zip_end(data: bytes, start: int) -> int | None:
    cursor = start
    while True:
        eocd = data.find(b"PK\x05\x06", cursor)
        if eocd < 0 or eocd + 22 > len(data):
            return None
        comment_length = struct.unpack_from("<H", data, eocd + 20)[0]
        end = eocd + 22 + comment_length
        if end <= len(data):
            return end
        cursor = eocd + 4


def _gzip_end(data: bytes, start: int) -> int | None:
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        candidate = data[start:]
        decompressor.decompress(candidate, MAX_EXPANDED_BYTES)
        if not decompressor.eof:
            return None
        consumed = len(candidate) - len(decompressor.unused_data)
        return start + consumed if consumed > 18 else None
    except zlib.error:
        return None


def _elf_end(data: bytes, start: int) -> int | None:
    try:
        if data[start:start + 4] != b"\x7fELF" or start + 16 > len(data):
            return None
        elf_class = data[start + 4]
        byte_order = data[start + 5]
        if elf_class not in {1, 2} or byte_order not in {1, 2}:
            return None
        endian = "<" if byte_order == 1 else ">"
        if elf_class == 1:
            if start + 52 > len(data):
                return None
            e_phoff = struct.unpack_from(endian + "I", data, start + 28)[0]
            e_shoff = struct.unpack_from(endian + "I", data, start + 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, start + 42)
            e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, start + 46)
            ph_offset_field, ph_size_field = 4, 16
            sh_offset_field, sh_size_field = 16, 20
        else:
            if start + 64 > len(data):
                return None
            e_phoff = struct.unpack_from(endian + "Q", data, start + 32)[0]
            e_shoff = struct.unpack_from(endian + "Q", data, start + 40)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, start + 54)
            e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, start + 58)
            ph_offset_field, ph_size_field = 8, 32
            sh_offset_field, sh_size_field = 24, 32
        maximum = 64 if elf_class == 2 else 52
        for table_offset, entry_size, count, off_field, size_field in (
            (e_phoff, e_phentsize, e_phnum, ph_offset_field, ph_size_field),
            (e_shoff, e_shentsize, e_shnum, sh_offset_field, sh_size_field),
        ):
            if not table_offset or not entry_size or count > 4096:
                continue
            table_end = table_offset + entry_size * count
            maximum = max(maximum, table_end)
            for index in range(count):
                entry = start + table_offset + entry_size * index
                if entry + max(off_field, size_field) + (8 if elf_class == 2 else 4) > len(data):
                    break
                fmt = "Q" if elf_class == 2 else "I"
                file_offset = struct.unpack_from(endian + fmt, data, entry + off_field)[0]
                file_size = struct.unpack_from(endian + fmt, data, entry + size_field)[0]
                maximum = max(maximum, file_offset + file_size)
        end = start + maximum
        return end if start < end <= len(data) and maximum <= MAX_BLOB_BYTES else None
    except (IndexError, struct.error):
        return None


def _pe_end(data: bytes, start: int) -> int | None:
    try:
        if data[start:start + 2] != b"MZ" or start + 0x40 > len(data):
            return None
        pe_offset = struct.unpack_from("<I", data, start + 0x3C)[0]
        pe = start + pe_offset
        if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\x00\x00":
            return None
        section_count = struct.unpack_from("<H", data, pe + 6)[0]
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        if section_count > 512:
            return None
        section_table = pe + 24 + optional_size
        maximum = section_table + section_count * 40
        for index in range(section_count):
            entry = section_table + index * 40
            if entry + 40 > len(data):
                return None
            raw_size = struct.unpack_from("<I", data, entry + 16)[0]
            raw_offset = struct.unpack_from("<I", data, entry + 20)[0]
            maximum = max(maximum, start + raw_offset + raw_size)
        return maximum if start < maximum <= len(data) and maximum - start <= MAX_BLOB_BYTES else None
    except struct.error:
        return None


def _sqlite_end(data: bytes, start: int) -> int | None:
    try:
        if data[start:start + 16] != b"SQLite format 3\x00" or start + 100 > len(data):
            return None
        page_size = struct.unpack_from(">H", data, start + 16)[0]
        if page_size == 1:
            page_size = 65536
        page_count = struct.unpack_from(">I", data, start + 28)[0]
        size = page_size * page_count
        end = start + size
        return end if page_size >= 512 and page_count and end <= len(data) and size <= MAX_BLOB_BYTES else None
    except struct.error:
        return None


def embedded_file_ranges(data: bytes) -> Iterable[tuple[str, str, int, int]]:
    """Best-effort carving of common non-image file types with verifiable boundaries."""
    signatures = (
        (b"PK\x03\x04", "zip"),
        (b"%PDF-", "pdf"),
        (b"\x1f\x8b\x08", "gz"),
        (b"\x7fELF", "elf"),
        (b"MZ", "exe"),
        (b"SQLite format 3\x00", "sqlite"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"RIFF", "riff"),
    )
    yielded: set[tuple[int, int]] = set()
    for signature, kind in signatures:
        cursor = 0
        while (start := data.find(signature, cursor)) >= 0:
            end: int | None = None
            extension = kind
            if kind == "zip":
                end = _zip_end(data, start)
            elif kind == "pdf":
                eof = data.find(b"%%EOF", start + 5)
                if eof >= 0:
                    end = eof + 5
                    while end < len(data) and data[end] in b"\r\n \t":
                        end += 1
            elif kind == "gz":
                end = _gzip_end(data, start)
            elif kind == "elf":
                end = _elf_end(data, start)
            elif kind == "exe":
                end = _pe_end(data, start)
            elif kind == "sqlite":
                end = _sqlite_end(data, start)
            elif kind == "7z" and start + 32 <= len(data):
                next_offset = struct.unpack_from("<Q", data, start + 12)[0]
                next_size = struct.unpack_from("<Q", data, start + 20)[0]
                candidate = start + 32 + next_offset + next_size
                if start < candidate <= len(data) and candidate - start <= MAX_BLOB_BYTES:
                    end = candidate
            elif kind == "riff" and start + 12 <= len(data):
                size = struct.unpack_from("<I", data, start + 4)[0] + 8
                form = data[start + 8:start + 12]
                if form == b"WAVE":
                    extension = "wav"
                elif form == b"AVI ":
                    extension = "avi"
                else:
                    cursor = start + 4
                    continue
                if 12 <= size <= MAX_BLOB_BYTES and start + size <= len(data):
                    end = start + size
            if end and end > start and (start, end) not in yielded:
                yielded.add((start, end))
                yield kind, extension, start, end
                cursor = end
            else:
                cursor = start + max(1, len(signature))


def _zip_extension(data: bytes) -> str:
    """Give common ZIP-based formats a more useful extension."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = {name.lower() for name in archive.namelist()[:5000]}
    except (OSError, zipfile.BadZipFile):
        return "zip"
    if "androidmanifest.xml" in names:
        return "apk"
    if "[content_types].xml" in names and any(name.startswith("word/") for name in names):
        return "docx"
    if "[content_types].xml" in names and any(name.startswith("xl/") for name in names):
        return "xlsx"
    if "[content_types].xml" in names and any(name.startswith("ppt/") for name in names):
        return "pptx"
    if "meta-inf/manifest.mf" in names:
        return "jar"
    return "zip"


def _safe_member_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in {"", ".", ".."}]
    basename = parts[-1] if parts else "member.bin"
    basename = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._") or "member.bin"
    return basename[:160]


def extract_embedded_files(
    blobs: Iterable[tuple[str, bytes]],
    output: Path,
    *,
    force: bool,
    seed_paths: Sequence[Path] = (),
) -> tuple[list[dict[str, Any]], list[tuple[str, bytes]], list[str]]:
    """Carve embedded files and safely unpack ZIP-family containers recursively."""
    if output.exists() and any(output.iterdir()) and not force:
        raise ValueError(f"file extraction directory is not empty: {output} (use --force)")
    output.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, Any]] = []
    extracted_blobs: list[tuple[str, bytes]] = []
    diagnostics: list[str] = []
    seen: set[str] = set()
    expanded_bytes = 0
    queue: list[tuple[str, bytes, str, int]] = []

    for source, original in blobs:
        base = original[:MAX_BLOB_BYTES]
        queue.append((source, base, "plain", 0))
        if readable_ratio(base) >= 0.65:
            for encoding, decoded in decoded_variants(base, max_depth=2):
                if encoding != "plain":
                    queue.append((source, decoded, encoding, 0))

    def save_candidate(data: bytes, source: str, encoding: str, extension: str, origin: str, depth: int) -> None:
        nonlocal expanded_bytes
        if not data or len(artifacts) >= MAX_CARVED_FILES:
            return
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            return
        seen.add(digest)
        if extension == "zip":
            extension = _zip_extension(data)
        index = len(artifacts) + 1
        path = output / f"file-{index:03d}-{digest[:12]}.{extension}"
        path.write_bytes(data)
        mime, description = describe_file(path)
        artifact = {
            "path": str(path.resolve()),
            "source": source,
            "encoding": encoding,
            "origin": origin,
            "type": description,
            "mime": mime,
            "size": len(data),
            "sha256": digest,
        }
        artifacts.append(artifact)
        extracted_blobs.append((f"extracted file {path.name} from {source}", data[:MAX_BLOB_BYTES]))
        expanded_bytes += len(data)
        if depth < 3 and extension in {"zip", "apk", "jar", "docx", "xlsx", "pptx"}:
            queue.append((f"archive {path.name}", data, "plain", depth + 1))

    def enqueue_archive_members(archive: zipfile.ZipFile, source: str, depth: int) -> None:
        for info in archive.infolist()[:MAX_ARCHIVE_MEMBERS]:
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and stat.S_ISLNK(mode):
                diagnostics.append(f"ZIP symlink skipped: {info.filename}")
                continue
            if info.file_size > MAX_BLOB_BYTES:
                diagnostics.append(f"ZIP member skipped (> {MAX_BLOB_BYTES:,} bytes): {info.filename}")
                continue
            if expanded_bytes + info.file_size > MAX_EXPANDED_BYTES:
                diagnostics.append("Archive extraction stopped at expanded-byte safety limit")
                break
            try:
                with archive.open(info) as handle:
                    member = handle.read(MAX_BLOB_BYTES + 1)
            except (RuntimeError, OSError, zipfile.BadZipFile, NotImplementedError) as error:
                diagnostics.append(f"ZIP member skipped ({info.filename}): {error}")
                continue
            if len(member) > MAX_BLOB_BYTES:
                diagnostics.append(f"ZIP member skipped after read limit: {info.filename}")
                continue
            suffix = Path(_safe_member_name(info.filename)).suffix.lower().lstrip(".") or "bin"
            save_candidate(member, f"{source}!{info.filename}", "archive-member", suffix, "archive-member", depth)
            if depth < 3:
                queue.append((f"{source}!{info.filename}", member, "archive-member", depth + 1))
            if len(artifacts) >= MAX_CARVED_FILES:
                break

    def enqueue_tar_members(archive: tarfile.TarFile, source: str, depth: int) -> None:
        for member_info in archive.getmembers()[:MAX_ARCHIVE_MEMBERS]:
            if not member_info.isfile() or member_info.issym() or member_info.islnk():
                continue
            if member_info.size > MAX_BLOB_BYTES:
                diagnostics.append(f"TAR member skipped (> {MAX_BLOB_BYTES:,} bytes): {member_info.name}")
                continue
            if expanded_bytes + member_info.size > MAX_EXPANDED_BYTES:
                diagnostics.append("Archive extraction stopped at expanded-byte safety limit")
                break
            handle = archive.extractfile(member_info)
            if handle is None:
                continue
            try:
                member = handle.read(MAX_BLOB_BYTES + 1)
            finally:
                handle.close()
            if len(member) > MAX_BLOB_BYTES:
                diagnostics.append(f"TAR member skipped after read limit: {member_info.name}")
                continue
            suffix = Path(_safe_member_name(member_info.name)).suffix.lower().lstrip(".") or "bin"
            save_candidate(member, f"{source}!{member_info.name}", "archive-member", suffix, "archive-member", depth)
            if depth < 3:
                queue.append((f"{source}!{member_info.name}", member, "archive-member", depth + 1))
            if len(artifacts) >= MAX_CARVED_FILES:
                break

    # Directly inspect top-level archives too, so large ZIP/TAR inputs are not
    # limited by the per-blob carving window.
    for seed in seed_paths:
        try:
            if zipfile.is_zipfile(seed):
                with zipfile.ZipFile(seed) as archive:
                    enqueue_archive_members(archive, f"input archive {seed.name}", 0)
                continue
        except (OSError, zipfile.BadZipFile):
            pass
        try:
            if tarfile.is_tarfile(seed):
                with tarfile.open(seed, mode="r:*") as archive:
                    enqueue_tar_members(archive, f"input archive {seed.name}", 0)
        except (OSError, tarfile.TarError):
            pass

    processed_archives: set[str] = set()
    processed_tars: set[str] = set()
    while queue and len(artifacts) < MAX_CARVED_FILES and expanded_bytes < MAX_EXPANDED_BYTES:
        source, data, encoding, depth = queue.pop(0)
        for _, extension, begin, end in embedded_file_ranges(data):
            save_candidate(data[begin:end], source, encoding, extension, "carved", depth)
            if len(artifacts) >= MAX_CARVED_FILES or expanded_bytes >= MAX_EXPANDED_BYTES:
                break

        archive_digest = hashlib.sha256(data).hexdigest()
        if archive_digest not in processed_archives:
            try:
                archive = zipfile.ZipFile(io.BytesIO(data))
            except (OSError, zipfile.BadZipFile):
                archive = None
            if archive is not None:
                processed_archives.add(archive_digest)
                with archive:
                    enqueue_archive_members(archive, source, depth)
                continue

        if archive_digest not in processed_tars:
            try:
                archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
            except (OSError, tarfile.TarError):
                archive = None
            if archive is not None:
                processed_tars.add(archive_digest)
                with archive:
                    enqueue_tar_members(archive, source, depth)

    if len(artifacts) >= MAX_CARVED_FILES:
        diagnostics.append(f"File extraction stopped after {MAX_CARVED_FILES} unique file(s)")
    if expanded_bytes >= MAX_EXPANDED_BYTES:
        diagnostics.append(f"File extraction stopped after {MAX_EXPANDED_BYTES:,} expanded bytes")
    return artifacts, extracted_blobs, diagnostics


def image_ranges(data: bytes) -> Iterable[tuple[str, int, int]]:
    start = 0
    png_signature = b"\x89PNG\r\n\x1a\n"
    while (position := data.find(png_signature, start)) >= 0:
        cursor = position + len(png_signature)
        end = -1
        while cursor + 12 <= len(data):
            length = struct.unpack(">I", data[cursor:cursor + 4])[0]
            if length > MAX_BLOB_BYTES or cursor + 12 + length > len(data):
                break
            chunk_type = data[cursor + 4:cursor + 8]
            cursor += 12 + length
            if chunk_type == b"IEND":
                end = cursor
                break
        if end > position:
            yield "png", position, end
            start = end
        else:
            start = position + 1
    start = 0
    while (position := data.find(b"\xff\xd8\xff", start)) >= 0:
        end_marker = data.find(b"\xff\xd9", position + 3)
        if end_marker >= 0:
            yield "jpg", position, end_marker + 2
            start = end_marker + 2
        else:
            start = position + 1
    for signature, extension in ((b"GIF87a", "gif"), (b"GIF89a", "gif")):
        start = 0
        while (position := data.find(signature, start)) >= 0:
            trailer = data.find(b"\x3b", position + 13)
            if trailer >= 0:
                yield extension, position, trailer + 1
                start = trailer + 1
            else:
                start = position + 1
    start = 0
    while (position := data.find(b"BM", start)) >= 0:
        if position + 6 <= len(data):
            length = struct.unpack("<I", data[position + 2:position + 6])[0]
            if 14 <= length <= MAX_BLOB_BYTES and position + length <= len(data):
                yield "bmp", position, position + length
                start = position + length
                continue
        start = position + 1
    start = 0
    while (position := data.find(b"RIFF", start)) >= 0:
        if position + 12 <= len(data) and data[position + 8:position + 12] == b"WEBP":
            length = struct.unpack("<I", data[position + 4:position + 8])[0] + 8
            if 12 <= length <= MAX_BLOB_BYTES and position + length <= len(data):
                yield "webp", position, position + length
                start = position + length
                continue
        start = position + 1


def image_dimensions(data: bytes, extension: str) -> tuple[int, int] | None:
    try:
        if extension == "png" and len(data) >= 24:
            return struct.unpack(">II", data[16:24])
        if extension == "gif" and len(data) >= 10:
            return struct.unpack("<HH", data[6:10])
        if extension == "bmp" and len(data) >= 26:
            return struct.unpack("<ii", data[18:26])
        if extension == "webp" and data[12:16] == b"VP8X" and len(data) >= 30:
            width = int.from_bytes(data[24:27], "little") + 1
            height = int.from_bytes(data[27:30], "little") + 1
            return width, height
        if extension == "jpg":
            cursor = 2
            sof = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
            while cursor + 9 < len(data):
                if data[cursor] != 0xFF:
                    cursor += 1
                    continue
                marker = data[cursor + 1]
                if marker in sof:
                    height, width = struct.unpack(">HH", data[cursor + 5:cursor + 9])
                    return width, height
                if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
                    cursor += 2
                    continue
                length = struct.unpack(">H", data[cursor + 2:cursor + 4])[0]
                cursor += max(2, length + 2)
    except (IndexError, struct.error):
        return None
    return None


def extract_images(
    blobs: Iterable[tuple[str, bytes]],
    output: Path,
    *,
    force: bool,
    ocr: bool,
    timeout: int,
) -> tuple[list[dict[str, Any]], list[tuple[str, bytes]], list[str]]:
    if output.exists() and any(output.iterdir()) and not force:
        raise ValueError(f"image directory is not empty: {output} (use --force)")
    output.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, Any]] = []
    ocr_blobs: list[tuple[str, bytes]] = []
    diagnostics: list[str] = []
    seen: set[str] = set()
    tesseract = shutil.which("tesseract") if ocr else None
    ocr_count = 0
    ocr_limit_noted = False
    if ocr and not tesseract:
        diagnostics.append("OCR skipped: tesseract is not installed")
    for source, original in blobs:
        base = original[:MAX_BLOB_BYTES]
        variants: list[tuple[str, bytes]] = [("plain", base)]
        if readable_ratio(base) >= 0.65:
            variants.extend((encoding, decoded) for encoding, decoded in decoded_variants(base) if encoding != "plain")
        for encoding, decoded in variants:
            for extension, begin, end in image_ranges(decoded):
                image = decoded[begin:end]
                digest = hashlib.sha256(image).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                path = output / f"image-{len(artifacts) + 1:03d}-{digest[:12]}.{extension}"
                path.write_bytes(image)
                mime = f"image/{'jpeg' if extension == 'jpg' else extension}"
                if shutil.which("file"):
                    result = subprocess.run(["file", "-b", "--mime-type", str(path)], capture_output=True, text=True, errors="replace", check=False)
                    detected = result.stdout.strip()
                    if detected:
                        mime = detected
                if not mime.startswith("image/"):
                    path.unlink(missing_ok=True)
                    continue
                dimensions = image_dimensions(image, extension)
                artifact: dict[str, Any] = {
                    "path": str(path.resolve()),
                    "source": source,
                    "encoding": encoding,
                    "type": mime,
                    "size": len(image),
                    "sha256": digest,
                }
                if dimensions:
                    artifact["width"], artifact["height"] = dimensions
                if tesseract and ocr_count < 100:
                    ocr_count += 1
                    try:
                        result = subprocess.run(
                            [tesseract, str(path), "stdout", "--psm", "6"],
                            capture_output=True,
                            text=True,
                            errors="replace",
                            timeout=min(timeout, 30),
                            check=False,
                        )
                        recognized = result.stdout.strip()
                    except subprocess.TimeoutExpired:
                        recognized = ""
                        diagnostics.append(f"OCR timeout: {path.name}")
                    if recognized:
                        artifact["ocr"] = safe_text(recognized, 4000)
                        ocr_blobs.append((f"OCR from {path.name}", recognized.encode()))
                elif tesseract and not ocr_limit_noted:
                    diagnostics.append("OCR limited to the first 100 unique images")
                    ocr_limit_noted = True
                artifacts.append(artifact)
                if len(artifacts) >= 500:
                    diagnostics.append("Image extraction stopped after 500 unique images")
                    return artifacts, ocr_blobs, diagnostics
    return artifacts, ocr_blobs, diagnostics


def export_objects(runner: Tshark, output: Path, force: bool) -> list[dict[str, Any]]:
    if output.exists() and any(output.iterdir()) and not force:
        raise ValueError(f"export directory is not empty: {output} (use --force)")
    output.mkdir(parents=True, exist_ok=True)
    for protocol in EXPORT_PROTOCOLS:
        destination = output / protocol.replace("-", "_")
        destination.mkdir(parents=True, exist_ok=True)
        runner.run(("--export-objects", f"{protocol},{destination}"), check=False)
    artifacts = []
    for path in sorted(item for item in output.rglob("*") if item.is_file()):
        mime, description = describe_file(path)
        artifacts.append({"path": str(path.resolve()), "size": path.stat().st_size, "sha256": sha256_file(path), "type": description, "mime": mime})
    return artifacts


def write_filtered_capture(runner: Tshark, output: Path, force: bool) -> None:
    if output.exists() and not force:
        raise ValueError(f"filtered capture already exists: {output} (use --force)")
    if output.resolve() == runner.capture.resolve():
        raise ValueError("filtered output cannot replace the source capture")
    arguments = ("-Y", runner.display_filter or "", "-w", str(output))
    runner.run(arguments, include_filter=False)


def embed_tls_secrets(source: Path, keylog: Path, output: Path, force: bool) -> None:
    if shutil.which("editcap") is None:
        raise RuntimeError("editcap is required by --embed-secrets")
    if output.exists() and not force:
        raise ValueError(f"secret-bearing capture already exists: {output} (use --force)")
    if output.resolve() == source.resolve():
        raise ValueError("--embed-secrets cannot replace the source capture")
    result = subprocess.run(["editcap", "--inject-secrets", f"tls,{keylog}", str(source), str(output)], capture_output=True, text=True, errors="replace", check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "editcap failed")


def flow_to_dict(flow: Flow) -> dict[str, Any]:
    return {
        "protocol": flow.protocol,
        "endpoint_a": flow.endpoint_a,
        "endpoint_b": flow.endpoint_b,
        "packets": flow.packets,
        "bytes": flow.bytes,
        "first": flow.first,
        "last": flow.last,
        "duration": flow.duration,
    }


def extend_unique_matches(target: list[Match], extra: Iterable[Match]) -> None:
    existing = {(item.kind, item.value, item.source) for item in target}
    for item in extra:
        key = (item.kind, item.value, item.source)
        if key not in existing:
            existing.add(key)
            target.append(item)


def analyze(args: argparse.Namespace) -> Report:
    rc4_key = parse_rc4_key(args.rc4_key) if args.rc4_key else None
    xor_key = parse_xor_key(args.xor_key) if args.xor_key else None
    log_info: dict[str, Any] = {}
    log_findings: list[Finding] = []
    log_blobs: list[tuple[str, bytes]] = []
    if args.input_kind == "log":
        log_info, log_findings, log_blobs = analyze_log_file(args.input, args.top)

    if not args.pcap:
        info = {
            "path": str(args.input.resolve()),
            "format": log_info.get("kind", "log"),
            "size": args.input.stat().st_size,
            "sha256": sha256_file(args.input),
            "artifact_root": str(args.artifact_root.resolve()),
            "pic_up_version": VERSION,
        }
        input_blobs = list(file_chunks(args.input, label="input raw bytes"))
        scan_blobs = [*input_blobs, *log_blobs]
        if xor_key:
            scan_blobs.extend(xor_blob_variants(list(scan_blobs), xor_key))
        matches = scan_matches(scan_blobs, flag_prefix=args.flag_prefix, patterns=args.pattern, rc4_key=rc4_key, rc4_drop=args.rc4_drop)
        diagnostics: list[str] = []
        extracted_files, file_blobs, file_notes = extract_embedded_files(scan_blobs, args.extract_files, force=args.force, seed_paths=(args.input,))
        diagnostics.extend(file_notes)
        if file_blobs:
            extend_unique_matches(matches, scan_matches(file_blobs, flag_prefix=args.flag_prefix, patterns=args.pattern, rc4_key=rc4_key, rc4_drop=args.rc4_drop))
        images, ocr_blobs, image_notes = extract_images(
            [*scan_blobs, *file_blobs], args.extract_images, force=args.force, ocr=not args.no_ocr, timeout=args.timeout,
        )
        diagnostics.extend(image_notes)
        extend_unique_matches(matches, scan_matches(ocr_blobs, flag_prefix=args.flag_prefix, patterns=args.pattern, rc4_key=None, rc4_drop=0))
        if log_info.get("valid_tls_secret_lines"):
            diagnostics.append("This is a TLS key log; pass --capture FILE to decrypt and analyze its companion capture")
        return Report(
            file=info, protocols=[], hosts=[], conversations=[], streams=[], udp_streams=[], timeline=[],
            expert=[], protocol_details=[], credentials=[], iocs=[], xor=[], dns=[], http=[], tls=[],
            hostnames=[], findings=log_findings, matches=matches, exports=[], comments=[],
            covert=[], images=images, extracted_files=extracted_files, log=log_info, diagnostics=diagnostics,
        )

    runner = Tshark(
        args.pcap,
        display_filter=args.display_filter,
        keylog=args.tls_keylog,
        rsa_key=args.tls_rsa_key,
        rsa_address=args.tls_rsa_address,
        rsa_port=args.tls_rsa_port,
        rsa_protocol=args.tls_rsa_protocol,
        timeout=args.timeout,
    )
    info = capture_info(args.pcap)
    info["pic_up_version"] = VERSION
    info["tshark_version"] = command_version("tshark")
    info["capinfos_version"] = command_version("capinfos")
    info["artifact_root"] = str(args.artifact_root.resolve())
    if args.input_kind == "log":
        info["input_log"] = str(args.input.resolve())
    if args.display_filter:
        info["display_filter"] = args.display_filter
        info["filtered_packets"] = runner.count()
    protocols, hosts, flows, directed_times = build_inventory(runner, args.top)
    streams, tcp_packets, stream_blobs = tcp_stream_inventory(runner, args.top)
    udp_streams, udp_blobs = udp_stream_inventory(runner, args.top)
    timeline, timeline_total = timeline_inventory(runner, args.timeline_limit)
    expert = expert_inventory(runner, args.top)
    infrastructure = protocol_details(runner, args.top)
    credentials = credential_inventory(runner, args.top, args.show_secrets)
    iocs = ioc_inventory(runner, args.top)
    timeline_outputs = write_timeline(timeline, args.artifact_root, args.timeline_format)
    info["timeline_packets"] = timeline_total
    info["timeline_in_report"] = len(timeline)
    if timeline_outputs:
        info["timeline_outputs"] = timeline_outputs
    packet_blobs = [
        (f"TCP stream {packet.stream} frame {packet.frame} {packet.source} -> {packet.destination}", packet.payload)
        for packet in tcp_packets
    ]
    xor_findings, auto_xor_blobs = detect_repeating_xor(tcp_packets, args.top)
    dns, dns_findings, dns_blobs = dns_inventory(runner, args.top)
    http = http_inventory(runner, args.top)
    tls, tls_findings = tls_inventory(runner, args.top)
    hostnames = hostname_inventory(runner, args.top)
    comments, comment_blobs = capture_comments(runner, args.pcap)
    covert, covert_findings, covert_blobs = covert_channel_candidates(runner, args.top)
    findings = [
        *log_findings, *dns_findings, *tls_findings, *covert_findings,
        *operational_findings(runner, directed_times, args.top),
    ]
    if expert:
        severities = Counter(item["severity"] or "unknown" for item in expert)
        findings.append(Finding("info", "Expert", "Wireshark Expert Info events", ", ".join(f"{name}={count}" for name, count in severities.most_common())))
    if credentials:
        protocols_with_credentials = Counter(item["protocol"] for item in credentials)
        findings.append(Finding("high", "Credentials", "Clear-text authentication material", ", ".join(f"{name}={count}" for name, count in protocols_with_credentials.most_common())))

    raw_capture_blobs = [] if args.display_filter else list(raw_chunks(args.pcap))
    blobs = [
        *raw_capture_blobs, *payload_blobs(runner), *stream_blobs, *udp_blobs, *packet_blobs, *auto_xor_blobs,
        *dns_blobs, *comment_blobs, *covert_blobs, *log_blobs,
    ]
    if xor_key:
        blobs.extend(xor_blob_variants([*stream_blobs, *packet_blobs], xor_key))
    matches = scan_matches(blobs, flag_prefix=args.flag_prefix, patterns=args.pattern, rc4_key=rc4_key, rc4_drop=args.rc4_drop)
    diagnostics = []
    if info.get("capinfos") == "unavailable":
        diagnostics.append("capinfos is unavailable; basic metadata and SHA-256 were collected without it")
    if args.tls_keylog:
        decrypted_http = runner.count("http || http2")
        diagnostics.append(f"TLS key log active; {decrypted_http} HTTP/HTTP2 packet(s) visible")
    if args.tls_rsa_key:
        diagnostics.append("Legacy RSA key configured; works only for compatible TLS RSA key exchanges, not TLS 1.3 or (EC)DHE")
    if args.rc4_key:
        diagnostics.append("RC4 was attempted independently on each extracted payload/stream candidate")
    if args.xor_key:
        diagnostics.append(f"Repeating XOR key {xor_key.hex()} was applied to each TCP payload and reassembled direction")
    if xor_findings:
        findings.append(Finding("high", "Crypto", "Validated repeating-XOR challenge/response", f"{len(xor_findings)} candidate(s) produced readable plaintext in the same TCP stream"))
    if args.display_filter:
        diagnostics.append("Raw whole-capture scanning was disabled so flag/pattern results respect the display filter")
    if timeline_total > len(timeline):
        diagnostics.append(f"Timeline report capped at {len(timeline):,} of {timeline_total:,} packets; use --timeline-limit to adjust it")
    if credentials and not args.show_secrets:
        diagnostics.append("Clear-text credential values are redacted; use --show-secrets only in a controlled environment")
    if args.pcap.stat().st_size > MAX_RAW_SCAN_BYTES:
        diagnostics.append(f"Raw capture scanning limited to the first {MAX_RAW_SCAN_BYTES:,} bytes; decoded payloads were still inspected")

    exports = export_objects(runner, args.export_dir, args.force) if args.export_dir else []
    export_blobs: list[tuple[str, bytes]] = []
    for artifact in exports:
        path = Path(artifact["path"])
        if path.stat().st_size <= MAX_BLOB_BYTES:
            export_blobs.append((f"exported object {path.name}", path.read_bytes()))
    if export_blobs:
        extend_unique_matches(matches, scan_matches(export_blobs, flag_prefix=args.flag_prefix, patterns=args.pattern, rc4_key=rc4_key, rc4_drop=args.rc4_drop))

    extraction_blobs = [*blobs, *export_blobs]
    extracted_files, file_blobs, file_notes = extract_embedded_files(extraction_blobs, args.extract_files, force=args.force, seed_paths=(args.input,))
    diagnostics.extend(file_notes)
    if file_blobs:
        extend_unique_matches(matches, scan_matches(file_blobs, flag_prefix=args.flag_prefix, patterns=args.pattern, rc4_key=rc4_key, rc4_drop=args.rc4_drop))

    images, ocr_blobs, image_notes = extract_images(
        [*extraction_blobs, *file_blobs], args.extract_images, force=args.force,
        ocr=not args.no_ocr, timeout=args.timeout,
    )
    diagnostics.extend(image_notes)
    extend_unique_matches(matches, scan_matches(ocr_blobs, flag_prefix=args.flag_prefix, patterns=args.pattern, rc4_key=None, rc4_drop=0))

    if args.write_filtered:
        write_filtered_capture(runner, args.write_filtered, args.force)
        info["filtered_output"] = str(args.write_filtered.resolve())
        info["filtered_sha256"] = sha256_file(args.write_filtered)
    if args.embed_secrets and args.tls_keylog:
        embed_tls_secrets(args.pcap, args.tls_keylog, args.embed_secrets, args.force)
        info["secret_bearing_copy"] = str(args.embed_secrets.resolve())
        info["secret_bearing_sha256"] = sha256_file(args.embed_secrets)

    return Report(
        file=info,
        protocols=protocols,
        hosts=hosts,
        conversations=[flow_to_dict(flow) for flow in flows],
        streams=streams,
        udp_streams=udp_streams,
        timeline=timeline,
        expert=expert,
        protocol_details=infrastructure,
        credentials=credentials,
        iocs=iocs,
        xor=xor_findings,
        dns=dns,
        http=http,
        tls=tls,
        hostnames=hostnames,
        findings=findings,
        matches=matches,
        exports=exports,
        comments=comments,
        covert=covert,
        images=images,
        extracted_files=extracted_files,
        log=log_info,
        diagnostics=diagnostics,
    )


def print_report(report: Report, colors: bool, top: int) -> None:
    print(paint(f"pic-up {VERSION} — CTF Network Triage", "magenta", colors))
    section("Input", colors)
    for key in ("path", "format", "encapsulation", "size", "packets", "first_packet", "last_packet", "duration", "sha256"):
        if key in report.file:
            print(paint(f"[•] {key:<18} {report.file[key]}", "white" if key != "sha256" else "blue", colors))
    if "artifact_root" in report.file:
        print(paint(f"[+] artifacts          {report.file['artifact_root']}", "green", colors))
    if "display_filter" in report.file:
        print(paint(f"[=] filter             {report.file['display_filter']}", "yellow", colors))
        print(paint(f"[=] matching packets   {report.file.get('filtered_packets', 0)}", "yellow", colors))

    if report.log:
        section("Log inventory", colors)
        print(paint(f"[LOG] type={report.log.get('kind', 'text log')} lines={report.log.get('lines', 0)} scanned={report.log.get('bytes_scanned', 0)} byte(s)", "cyan", colors))
        for label, values in (("IP", report.log.get("top_ips", {})), ("DOMAIN", report.log.get("top_domains", {})), ("URL", report.log.get("top_urls", {}))):
            for value, count in list(values.items())[:top]:
                print(paint(f"[{label}] {count:>5}  {value}", "blue", colors))
        if report.log.get("tls_secret_labels"):
            labels = ", ".join(f"{name}={count}" for name, count in report.log["tls_secret_labels"].items())
            print(paint(f"[TLS-KEYLOG] valid={report.log.get('valid_tls_secret_lines', 0)} | {labels}", "green", colors))

    section("Protocols", colors)
    for item in report.protocols:
        print(paint(f"[=] {item['protocol']:<24} {item['packets']:>9} packet(s)", "blue", colors))

    section("Hosts", colors)
    for item in report.hosts[:top]:
        print(paint(f"[•] {item['address']:<39} pkts={item['packets']:<7} bytes={item['bytes']}", "white", colors))

    section("Top conversations", colors)
    for item in report.conversations[:top]:
        print(paint(f"[{item['protocol']}] {item['endpoint_a']} ↔ {item['endpoint_b']} | pkts={item['packets']} bytes={item['bytes']} duration={item['duration']:.3f}s", "cyan", colors))

    section("TCP stream transcripts", colors)
    if report.streams:
        for stream in report.streams[:top]:
            print(paint(f"[STREAM {stream['stream']}] {' ↔ '.join(stream['endpoints'])} | payload-pkts={stream['payload_packets']} bytes={stream['payload_bytes']} frames={stream['first_frame']}–{stream['last_frame']}", "cyan", colors))
            for direction in stream["directions"]:
                frames = ",".join(map(str, direction["frames"][:20]))
                print(paint(f"  [→] {direction['source']} → {direction['destination']} | frames={frames} reassembled={direction['reassembled_bytes']} byte(s)", "white", colors))
                print(paint(f"      text: {direction['preview'] or '—'}", "dim", colors))
                print(paint(f"      hex:  {direction['hex_preview'] or '—'}", "dim", colors))
    else:
        print(paint("[—] No TCP application payloads.", "dim", colors))

    section("UDP pseudo-sessions", colors)
    if report.udp_streams:
        for stream in report.udp_streams[:top]:
            print(paint(f"[UDP {stream['stream']}] {' ↔ '.join(stream['endpoints'])} | datagrams={stream['datagrams']} payload={stream['payload_bytes']} byte(s) frames={stream['first_frame']}–{stream['last_frame']}", "cyan", colors))
            for packet in stream["packets"][:3]:
                print(paint(f"  [#{packet['frame']}] {packet['source']} → {packet['destination']} | {packet['payload_bytes']} byte(s) | {packet['preview'] or '—'}", "dim", colors))
    else:
        print(paint("[—] No UDP datagrams.", "dim", colors))

    if report.xor:
        section("Repeating-XOR recovery", colors)
        for item in report.xor[:top]:
            print(paint(f"[XOR] stream {item['stream']} key={item['key_hex']} ({item['key_bytes']} byte(s)) confidence={item['confidence']:.1%}", "green", colors))
            print(paint(f"      known frames {item['known_frames']} → decrypted frame {item['target_frame']}", "yellow", colors))
            print(paint(f"      plaintext: {item['plaintext_preview']}", "white", colors))

    section("DNS and host identifiers", colors)
    shown = False
    for item in report.dns[:top]:
        if "query" in item:
            print(paint(f"[DNS] {item['count']:>5}  {item['query']}", "blue", colors))
            shown = True
    for item in report.hostnames[:top]:
        print(paint(f"[HOST] frame {item['frame']}: {item['source']} → {', '.join(item['names'])}", "blue", colors))
        shown = True
    if not shown:
        print(paint("[—] No DNS queries or advertised hostnames.", "dim", colors))

    section("HTTP", colors)
    if report.http:
        for item in report.http[:top]:
            request = f"{item['method']} {item['host']}{item['uri']}".strip()
            response = f"status={item['status']} type={item['content_type']} len={item['content_length']}".strip()
            print(paint(f"[HTTP] frame {item['frame']} {item['source']} → {item['destination']} | {request or response}", "green", colors))
    else:
        print(paint("[—] No decoded HTTP transactions.", "dim", colors))

    section("TLS", colors)
    if report.tls:
        for item in report.tls[:top]:
            print(paint(f"[TLS] frame {item['frame']} {item['source']} → {item['destination']}:{item['port']} | type={item['handshake']} SNI={item['sni'] or '—'} ALPN={item['alpn'] or '—'} JA3={item['ja3'] or '—'} JA4={item['ja4'] or '—'}", "green", colors))
    else:
        print(paint("[—] No TLS handshakes decoded.", "dim", colors))

    if report.protocol_details:
        section("Infrastructure protocols", colors)
        for item in report.protocol_details[:top]:
            details = ", ".join(f"{key}={value}" for key, value in item["details"].items())
            print(paint(f"[{item['protocol']}] {item['packets']} packet(s), first frame {item['first_frame']} | {details}", "blue", colors))

    if report.credentials:
        section("Clear-text credentials", colors)
        for item in report.credentials[:top]:
            print(paint(f"[CREDENTIAL] frame {item['frame']} {item['protocol']} {item['kind']} {item['source']} → {item['destination']} | {item['value']} len={item['length']} sha256={item['sha256']}", "red", colors))

    if report.iocs:
        section("Indicators", colors)
        for item in report.iocs[:top]:
            print(paint(f"[IOC:{item['type']}] {item['value']} | count={item['count']} frames={','.join(map(str, item['frames'][:8]))} source={','.join(item['sources'])}", "yellow", colors))

    if report.expert:
        section("Wireshark Expert Info", colors)
        for item in report.expert[:top]:
            print(paint(f"[EXPERT] frame {item['frame']} {item['severity']}/{item['group']} | {item['message']}", "yellow", colors))

    if report.timeline:
        section("Timeline", colors)
        print(paint(f"[=] {len(report.timeline)} normalized packet event(s) included", "blue", colors))
        for path in report.file.get("timeline_outputs", []):
            print(paint(f"[+] {path}", "green", colors))

    section("CTF matches", colors)
    if report.matches:
        for item in report.matches[:100]:
            color = "green" if item.kind == "flag" else "yellow"
            print(paint(f"[OK] {item.kind} ({item.encoding}) {item.value}", color, colors))
            print(paint(f"     source: {item.source}", "dim", colors))
    else:
        print(paint("[—] No flag or requested pattern found.", "dim", colors))

    section("Findings", colors)
    if report.findings:
        color_map = {"high": "red", "medium": "yellow", "info": "blue"}
        for item in report.findings[:100]:
            print(paint(f"[{item.severity.upper()}] {item.category}: {item.summary}", color_map.get(item.severity, "white"), colors))
            print(paint(f"       {item.evidence}", "dim", colors))
    else:
        print(paint("[OK] No configured anomaly triggered.", "green", colors))

    if report.exports:
        section("Exported objects", colors)
        for item in report.exports[:100]:
            print(paint(f"[+] {item['path']} | {item['size']} bytes | {item['type']}", "green", colors))
            print(paint(f"    sha256 {item['sha256']}", "blue", colors))
    if report.comments:
        section("PCAPNG comments", colors)
        for item in report.comments[:100]:
            location = f"frame {item.get('frame')}" if item.get("frame") else "capture"
            print(paint(f"[COMMENT] {location}: {item['value']}", "yellow", colors))
    if report.covert:
        section("Covert-channel candidates", colors)
        for item in report.covert[:top]:
            print(paint(f"[COVERT] {item['source']} | {item['bytes']} byte(s) | readable={item['readable_ratio']:.1%}", "yellow", colors))
            print(paint(f"         {item['preview']}", "dim", colors))
    if report.extracted_files:
        section("Extracted files", colors)
        for item in report.extracted_files[:100]:
            print(paint(f"[FILE] {item['path']} | {item['type']} | {item['size']} bytes", "green", colors))
            print(paint(f"       source: {item['source']} ({item['origin']}, {item['encoding']})", "dim", colors))
            print(paint(f"       sha256 {item['sha256']}", "blue", colors))
    if report.images:
        section("Extracted images", colors)
        for item in report.images[:100]:
            dimensions = f" {item.get('width')}x{item.get('height')}" if item.get("width") and item.get("height") else ""
            print(paint(f"[IMAGE] {item['path']} | {item['type']}{dimensions} | {item['size']} bytes", "green", colors))
            print(paint(f"        source: {item['source']} ({item['encoding']})", "dim", colors))
            if item.get("ocr"):
                print(paint(f"        OCR: {item['ocr']}", "yellow", colors))
    if report.diagnostics:
        section("Notes", colors)
        for message in report.diagnostics:
            print(paint(f"[i] {message}", "blue", colors))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pic-up",
        description="Fast, colored PCAP/PCAPNG and generic file/log triage for authorized CTF and forensic analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  pic-up capture.pcapng
  pic-up capture.pcapng --all
  pic-up evidence.bin --all --output-dir ./case-artifacts
  pic-up capture.pcapng -f HTB -p 'password|token'
  pic-up capture.pcapng --tls-keylog sslkeys.log
  pic-up sslkeys.log --capture capture.pcapng --all
  pic-up capture.pcapng --rc4-key hex:001122334455
  pic-up capture.pcapng --xor-key hex:1c4ece63519493eb -f flag
  pic-up capture.pcapng -Y 'http || dns' --write-filtered filtered.pcapng

Automatic behavior:
  Every input is scanned for embedded files and images. Results are written under
  <input-stem>_picup/{files,images}. --all additionally exports protocol objects
  from captures to <input-stem>_picup/objects. Actions that need user-supplied
  artifacts (custom flag/pattern, filters, TLS/RSA/RC4/XOR secrets, filtered output,
  secret embedding) are never guessed by --all.
""",
    )
    parser.add_argument("input", type=Path, help="PCAP, PCAPNG, log, or generic file to analyze (required)")
    parser.add_argument("--all", action="store_true", help="run every self-contained action; excludes actions requiring user-supplied secrets, keys, prefixes, patterns, or filters")
    parser.add_argument("--output-dir", type=Path, metavar="DIR", help="root directory for automatic artifacts (default: <input-stem>_picup, non-destructive suffix on reruns)")
    parser.add_argument("--capture", type=Path, metavar="PCAP", help="companion capture when the main input is a TLS key .log")
    parser.add_argument("-f", "--flag-prefix", action="append", help="expected flag prefix; repeat for multiple prefixes")
    parser.add_argument("-p", "--pattern", action="append", default=[], metavar="REGEX", help="case-insensitive regex to search; repeatable")
    parser.add_argument("-Y", "--filter", dest="display_filter", help="Wireshark display filter applied to the analysis")
    parser.add_argument("--write-filtered", type=Path, metavar="PCAPNG", help="write packets matching --filter to a derived capture")
    parser.add_argument("--tls-keylog", type=Path, metavar="FILE", help="NSS/RFC 9850 TLS key log")
    parser.add_argument("--tls-rsa-key", type=Path, metavar="PEM", help="legacy RSA private key (limited to RSA key exchange)")
    parser.add_argument("--tls-rsa-address", default="0.0.0.0", help="server address for --tls-rsa-key")
    parser.add_argument("--tls-rsa-port", type=int, default=0, help="server port for --tls-rsa-key (default: 0/any)")
    parser.add_argument("--tls-rsa-protocol", default="http", help="decrypted application protocol for --tls-rsa-key")
    parser.add_argument("--embed-secrets", type=Path, metavar="PCAPNG", help="create a sensitive PCAPNG copy containing --tls-keylog secrets")
    parser.add_argument("--rc4-key", metavar="KEY", help="RC4 key as text, hex:..., or base64:...")
    parser.add_argument("--rc4-drop", type=int, default=0, metavar="N", help="discard N initial RC4 keystream bytes")
    parser.add_argument("--xor-key", metavar="KEY", help="repeating-XOR key as text, hex:..., or base64:...; auto-detection runs without this option")
    parser.add_argument("--export-dir", type=Path, help="export HTTP/FTP/SMB/TFTP/IMF objects and hash them; enabled automatically by --all for captures")
    parser.add_argument("--extract-files", type=Path, metavar="DIR", help="override automatic embedded-file extraction directory")
    parser.add_argument("--extract-images", type=Path, metavar="DIR", help="override automatic PNG/JPEG/GIF/BMP/WebP carving directory")
    parser.add_argument("--no-ocr", action="store_true", help="do not run Tesseract OCR on extracted images")
    parser.add_argument("--top", type=int, default=DEFAULT_TOP, help=f"maximum rows per inventory section (default: {DEFAULT_TOP})")
    parser.add_argument("--timeline-limit", type=int, default=5000, metavar="N", help="maximum normalized packet events kept in the report (default: 5000)")
    parser.add_argument("--timeline", dest="timeline_format", choices=("none", "jsonl", "csv", "both"), default="none", help="write the normalized packet timeline; --all selects both")
    parser.add_argument("--show-secrets", action="store_true", help="show clear-text credential values (redacted by default; sensitive)")
    parser.add_argument("--timeout", type=int, default=120, help="timeout for each TShark pass in seconds")
    parser.add_argument("--force", action="store_true", help="allow overwriting derived outputs or using non-empty explicit output directories")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable JSON report")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="color mode (default: auto)")
    parser.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_inputs(args, parser)
    configure_automatic_actions(args)
    if args.top <= 0:
        parser.error("--top must be greater than zero")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.timeline_limit <= 0:
        parser.error("--timeline-limit must be greater than zero")
    colors = not args.json and not args.no_color and (
        args.color == "always" or (args.color == "auto" and sys.stdout.isatty())
    )
    try:
        report = analyze(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(paint(f"[ERROR] {error}", "red", colors), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(asdict(report), ensure_ascii=False, indent=2))
    else:
        print_report(report, colors, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
