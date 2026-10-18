from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..scanner import ScanConfig, scan_bytes
from ..util import iter_files

SECRET_RE = re.compile(r"(?i)\b(token|cookie|session(?:_id)?|authorization)\b\s*[:=]\s*([\"']?)[^\s,}\"']+\2")


def redact(text: str) -> tuple[str, bool]:
    changed = bool(SECRET_RE.search(text))
    return SECRET_RE.sub(lambda m: f"{m.group(1)}=<REDACTED>", text), changed


def slack_time(value: str, timezone: str = "Europe/Rome") -> tuple[str | None, str | None]:
    try:
        stamp = datetime.fromtimestamp(float(value), UTC)
        try:
            from zoneinfo import ZoneInfo
            local = stamp.astimezone(ZoneInfo(timezone))
        except Exception:
            local = stamp
        return stamp.isoformat(), local.isoformat()
    except (TypeError, ValueError, OverflowError):
        return None, None


def analyze(root: Path, config: ScanConfig, timezone: str = "Europe/Rome") -> dict[str, Any]:
    users: dict[str, dict[str, Any]] = {}
    channels: dict[str, dict[str, Any]] = {}
    messages: list[dict[str, Any]] = []
    findings = []
    warnings = []
    for path in iter_files(root,limit=10_000,diagnostics=config.diagnostics):
        if path.suffix.lower() not in (".json", ".log", ".ldb"):
            continue
        raw = config.read_prefix(path,8*1024*1024 if path.suffix.lower()==".json" else 64*1024*1024)
        findings.extend(scan_bytes(raw, source=str(root), path=str(path), module="slack", config=config))
        if path.suffix.lower() != ".json":
            continue
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeError):
            continue
        if path.name == "users.json" and isinstance(data, list):
            for user in data:
                if isinstance(user, dict) and user.get("id"):
                    profile = user.get("profile") or {}
                    users[user["id"]] = {"id": user["id"], "name": user.get("name"), "display_name": profile.get("display_name"), "email": profile.get("email")}
        elif path.name in {"channels.json", "groups.json", "dms.json", "mpims.json"} and isinstance(data, list):
            for channel in data:
                if isinstance(channel, dict) and channel.get("id"):
                    channels[channel["id"]] = channel
        elif isinstance(data, list):
            channel_name = path.parent.name
            for msg in data[:100_000]:
                if len(messages)>=100_000:
                    config.warn("Slack message inventory limited to 100,000 records")
                    break
                if not isinstance(msg, dict) or not (msg.get("text") or msg.get("subtype")):
                    continue
                text, secret = redact(str(msg.get("text", ""))[:16_384])
                utc, local = slack_time(str(msg.get("ts", "")), timezone)
                reactions=msg.get("reactions",[]);attachments=msg.get("files",[]) or msg.get("attachments",[])
                messages.append({"author": msg.get("user") or msg.get("username"), "channel": channel_name,
                                 "thread": msg.get("thread_ts"), "text": text, "timestamp_utc": utc,
                                 "timestamp_local": local, "reactions": reactions[:32] if isinstance(reactions,list) else [],
                                 "attachments": attachments[:32] if isinstance(attachments,list) else [],
                                 "edited": msg.get("edited"), "source": str(path), "credentials_redacted": secret,
                                 "confidence": 1.0})
    return {"users": list(users.values()), "channels": list(channels.values()), "messages": messages, "findings": findings, "warnings": warnings}
