"""Portable, evidence-oriented network inventories built on TShark fields.

The functions in this module deliberately depend on a tiny ``fields``/``count``
runner protocol.  This keeps them independently testable and lets the CLI adapt
to different TShark releases without importing presentation or carving code.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, Sequence


class FieldRunner(Protocol):
    def fields(self, fields: Sequence[str], display_filter: str | None = None) -> list[list[str]]: ...


def _number(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _text(value: bytes | str, limit: int = 240) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    cleaned = "".join(char if char.isprintable() else "." for char in value)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def _hex(value: str) -> bytes:
    try:
        return bytes.fromhex(value.replace(":", "")) if value else b""
    except ValueError:
        return b""


def _endpoint(address: str, port: str) -> str:
    if not address:
        return "?"
    if ":" in address:
        address = f"[{address}]"
    return f"{address}:{port or '?'}"


def _iso8601(epoch: str) -> str:
    value = _number(epoch)
    if not value:
        return ""
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def timeline_inventory(runner: FieldRunner, limit: int) -> tuple[list[dict[str, Any]], int]:
    """Return a normalized packet timeline and the uncapped packet count."""
    fields = (
        "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
        "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "_ws.col.Info",
    )
    rows = runner.fields(fields)
    events: list[dict[str, Any]] = []
    for row in rows[:limit]:
        source = row[6] or row[8] or row[4]
        destination = row[7] or row[9] or row[5]
        transport = "TCP" if row[10] or row[11] else "UDP" if row[12] or row[13] else ""
        source_port = row[10] or row[12]
        destination_port = row[11] or row[13]
        events.append({
            "frame": int(_number(row[0])),
            "epoch": _number(row[1]),
            "time_utc": _iso8601(row[1]),
            "length": int(_number(row[2])),
            "protocols": row[3].split(":") if row[3] else [],
            "source": source,
            "destination": destination,
            "source_port": int(_number(source_port)) if source_port else None,
            "destination_port": int(_number(destination_port)) if destination_port else None,
            "transport": transport,
            "summary": _text(row[14], 500),
        })
    return events, len(rows)


def write_timeline(events: list[dict[str, Any]], root: Path, output_format: str) -> list[str]:
    """Write deterministic JSONL/CSV timeline artifacts and return their paths."""
    if output_format == "none":
        return []
    root.mkdir(parents=True, exist_ok=True)
    outputs: list[str] = []
    if output_format in {"jsonl", "both"}:
        path = root / "timeline.jsonl"
        with path.open("w", encoding="utf-8", newline="") as handle:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        outputs.append(str(path.resolve()))
    if output_format in {"csv", "both"}:
        path = root / "timeline.csv"
        columns = ("frame", "epoch", "time_utc", "length", "transport", "source", "source_port", "destination", "destination_port", "protocols", "summary")
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for event in events:
                row = dict(event)
                row["protocols"] = ":".join(event["protocols"])
                writer.writerow(row)
        outputs.append(str(path.resolve()))
    return outputs


def udp_stream_inventory(runner: FieldRunner, top: int) -> tuple[list[dict[str, Any]], list[tuple[str, bytes]]]:
    """Build direction-aware UDP pseudo-sessions while preserving datagrams."""
    fields = (
        "frame.number", "frame.time_epoch", "udp.stream", "ip.src", "ipv6.src",
        "udp.srcport", "ip.dst", "ipv6.dst", "udp.dstport", "udp.length", "udp.payload",
    )
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in runner.fields(fields, "udp"):
        source = _endpoint(row[3] or row[4], row[5])
        destination = _endpoint(row[6] or row[7], row[8])
        payload = _hex(row[10])
        stream = row[2] or f"{min(source, destination)}|{max(source, destination)}"
        grouped[stream].append({
            "frame": int(_number(row[0])), "epoch": _number(row[1]),
            "source": source, "destination": destination,
            "length": int(_number(row[9])), "payload": payload,
        })
    sessions: list[dict[str, Any]] = []
    blobs: list[tuple[str, bytes]] = []
    for stream, datagrams in grouped.items():
        datagrams.sort(key=lambda item: (item["frame"], item["epoch"]))
        directions: Counter[str] = Counter()
        wire_bytes = 0
        payload_bytes = 0
        rendered: list[dict[str, Any]] = []
        for datagram in datagrams:
            payload = datagram.pop("payload")
            direction = f"{datagram['source']} -> {datagram['destination']}"
            directions[direction] += 1
            wire_bytes += datagram["length"]
            payload_bytes += len(payload)
            if payload:
                blobs.append((f"UDP stream {stream} frame {datagram['frame']} {direction}", payload))
            rendered.append({
                **datagram, "payload_bytes": len(payload),
                "preview": _text(payload, 160), "hex_preview": payload[:48].hex(),
            })
        sessions.append({
            "stream": int(stream) if stream.isdigit() else stream,
            "endpoints": sorted({item["source"] for item in rendered} | {item["destination"] for item in rendered}),
            "datagrams": len(rendered), "wire_bytes": wire_bytes, "payload_bytes": payload_bytes,
            "first_frame": rendered[0]["frame"], "last_frame": rendered[-1]["frame"],
            "directions": dict(directions), "packets": rendered[:100],
            "truncated": len(rendered) > 100,
        })
    sessions.sort(key=lambda item: (item["payload_bytes"], item["datagrams"]), reverse=True)
    return sessions[:top], blobs


def expert_inventory(runner: FieldRunner, top: int) -> list[dict[str, Any]]:
    fields = ("frame.number", "frame.time_epoch", "_ws.expert.severity", "_ws.expert.group", "_ws.expert.message")
    output: list[dict[str, Any]] = []
    for row in runner.fields(fields):
        if not (row[2] or row[3] or row[4]):
            continue
        messages = row[4].split(",") if row[4] else [""]
        output.append({
            "frame": int(_number(row[0])), "time": _iso8601(row[1]),
            "severity": row[2], "group": row[3], "message": _text("; ".join(messages), 500),
        })
        if len(output) >= max(top * 5, top):
            break
    return output


def protocol_details(runner: FieldRunner, top: int) -> list[dict[str, Any]]:
    """Summarize common infrastructure and authentication protocols in one pass."""
    fields = ("frame.number", "frame.protocols", "arp.opcode", "icmp.type", "icmpv6.type", "dhcp.option.dhcp", "ntp.flags.mode", "smb2.cmd", "kerberos.msg_type", "ssh.protocol")
    counters: dict[str, Counter[str]] = defaultdict(Counter)
    first_frames: dict[str, int] = {}
    for row in runner.fields(fields):
        protocols = set(row[1].split(":"))
        candidates = (
            ("ARP", row[2]), ("ICMP", row[3]), ("ICMPv6", row[4]),
            ("DHCP", row[5]), ("NTP", row[6]), ("SMB2", row[7]),
            ("Kerberos", row[8]), ("SSH", row[9]),
        )
        for name, detail in candidates:
            if detail or name.lower() in protocols or (name == "DHCP" and "bootp" in protocols):
                counters[name][detail or "present"] += 1
                first_frames.setdefault(name, int(_number(row[0])))
    rows = [
        {"protocol": name, "packets": sum(values.values()), "first_frame": first_frames[name], "details": dict(values.most_common(top))}
        for name, values in counters.items()
    ]
    return sorted(rows, key=lambda item: item["packets"], reverse=True)


def _secret(value: str, reveal: bool) -> dict[str, Any]:
    encoded = value.encode("utf-8", errors="replace")
    return {
        "value": _text(value, 500) if reveal else "<redacted>",
        "redacted": not reveal,
        "length": len(value),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def credential_inventory(runner: FieldRunner, top: int, reveal: bool = False) -> list[dict[str, Any]]:
    """Inventory clear-text authentication material; redact values by default."""
    fields = (
        "frame.number", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
        "http.authorization", "http.proxy_authorization", "ftp.request.command", "ftp.request.arg",
        "smtp.req.command", "smtp.req.parameter", "pop.request.command", "pop.request.parameter",
        "imap.request", "irc.request", "telnet.data",
    )
    output: list[dict[str, Any]] = []
    for row in runner.fields(fields):
        candidates: list[tuple[str, str, str]] = []
        if row[5]: candidates.append(("HTTP", "Authorization", row[5]))
        if row[6]: candidates.append(("HTTP", "Proxy-Authorization", row[6]))
        if row[7].upper() in {"USER", "PASS", "ACCT"} and row[8]: candidates.append(("FTP", row[7].upper(), row[8]))
        if row[9].upper() in {"AUTH", "MAIL", "RCPT"} and row[10]: candidates.append(("SMTP", row[9].upper(), row[10]))
        if row[11].upper() in {"USER", "PASS", "APOP", "AUTH"} and row[12]: candidates.append(("POP3", row[11].upper(), row[12]))
        if row[13] and any(token in row[13].upper() for token in (" LOGIN ", " AUTHENTICATE ")): candidates.append(("IMAP", "authentication", row[13]))
        if row[14] and any(token in row[14].upper() for token in ("PASS ", "OPER ", "AUTHENTICATE ")): candidates.append(("IRC", "authentication", row[14]))
        if row[15]: candidates.append(("Telnet", "data", row[15]))
        for protocol, kind, value in candidates:
            output.append({
                "frame": int(_number(row[0])), "source": row[1] or row[2], "destination": row[3] or row[4],
                "protocol": protocol, "kind": kind, **_secret(value, reveal),
            })
            if len(output) >= max(top * 5, top):
                return output
    return output


def ioc_inventory(runner: FieldRunner, top: int) -> list[dict[str, Any]]:
    """Collect deduplicated IP, domain, URL and email indicators with provenance."""
    fields = (
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "dns.qry.name", "dns.a", "dns.aaaa", "http.host", "http.request.uri",
        "tls.handshake.extensions_server_name", "smtp.req.parameter",
    )
    seen: dict[tuple[str, str], dict[str, Any]] = {}

    def add(kind: str, value: str, frame: int, epoch: float, source: str) -> None:
        value = value.strip().rstrip(".")
        if not value:
            return
        key = (kind, value.lower() if kind != "ip" else value)
        item = seen.get(key)
        if item is None:
            seen[key] = {"type": kind, "value": value, "count": 1, "first": epoch, "last": epoch, "frames": [frame], "sources": [source]}
            return
        item["count"] += 1
        item["first"] = min(item["first"], epoch)
        item["last"] = max(item["last"], epoch)
        if len(item["frames"]) < 20 and frame not in item["frames"]: item["frames"].append(frame)
        if source not in item["sources"]: item["sources"].append(source)

    for row in runner.fields(fields):
        frame, epoch = int(_number(row[0])), _number(row[1])
        for value in row[2:6]:
            for address in value.split(","):
                try:
                    add("ip", str(ipaddress.ip_address(address)), frame, epoch, "packet")
                except ValueError:
                    pass
        for source, value in (("dns_query", row[6]), ("http_host", row[9]), ("tls_sni", row[11])):
            for domain in value.split(","):
                if domain: add("domain", domain, frame, epoch, source)
        for value in (row[7] + "," + row[8]).split(","):
            try:
                add("ip", str(ipaddress.ip_address(value)), frame, epoch, "dns_answer")
            except ValueError:
                pass
        if row[9] and row[10]:
            scheme = "https" if row[11] and row[11].lower() == row[9].lower() else "http"
            add("url", f"{scheme}://{row[9]}{row[10]}", frame, epoch, "http")
        for email in row[12].replace("<", " ").replace(">", " ").split():
            if "@" in email: add("email", email.strip(",;"), frame, epoch, "smtp")
    output = list(seen.values())
    output.sort(key=lambda item: (item["count"], item["last"]), reverse=True)
    return output[: max(top * 5, top)]
