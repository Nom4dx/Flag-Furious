from __future__ import annotations

import hashlib
import itertools
import re
import shutil
import zlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from ..scanner import ScanConfig, scan_bytes
from ..models import Finding
from ..util import run, run_binary, safe_name

OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
LOOSE_OBJECT_LIMIT = 16 * 1024 * 1024
LOOSE_OBJECT_READ_SIZE = 64 * 1024
LOOSE_OBJECT_PREFIX_LIMIT = 4096
MAX_REPOSITORY_WARNINGS = 100
MAX_REPOSITORY_COMMANDS = 2_000


def _command_summary(record: dict[str, Any]) -> dict[str, Any]:
    """Retain bounded command evidence without copying captured output into reports."""
    stdout = record.get("stdout", "")
    stderr = record.get("stderr", "")
    return {
        **{key: value for key, value in record.items() if key not in {"stdout", "stderr"}},
        "stdout_bytes": int(record.get("stdout_bytes", len(stdout.encode("utf-8", "replace")) if isinstance(stdout, str) else len(stdout))),
        "stderr_bytes": int(record.get("stderr_bytes", len(stderr.encode("utf-8", "replace")) if isinstance(stderr, str) else len(stderr))),
        "stderr_preview": stderr[:2048] if isinstance(stderr, str) else "",
    }


def find_repositories(root: Path) -> list[dict[str, Any]]:
    candidates: dict[Path, str] = {}
    if root.is_dir():
        walked = 0
        for base, dirs, _files in os.walk(root, followlinks=False):
            walked += 1
            if walked > 10_000:
                break
            dirs[:] = sorted(name for name in dirs if not (Path(base) / name).is_symlink())
            for name in list(dirs):
                path = Path(base) / name
                if path.name == ".git":
                    candidates[path] = "worktree"
                    dirs.remove(name)
                elif (path / "HEAD").is_file() and (path / "objects").is_dir():
                    candidates[path] = "bare"
                elif (path / "objects" / "pack").is_dir() and any((path / "objects" / "pack").glob("*.pack")):
                    candidates[path] = "partial"
            if len(candidates) >= 100:
                break
    return [{"git_dir": str(path), "root": str(path.parent if kind == "worktree" else path), "type": kind} for path, kind in sorted(candidates.items(), key=lambda item: str(item[0]))]


def _git(git_dir: Path, args: list[str], timeout: int = 120) -> dict[str, Any]:
    return run(["git", f"--git-dir={git_dir}", *args], timeout=timeout)


def parse_loose_object(path: Path, oid: str | None = None) -> dict[str, Any] | None:
    try:
        decoder = zlib.decompressobj()
        raw = bytearray()
        compressed_bytes = 0
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            if os.fstat(source.fileno()).st_size > LOOSE_OBJECT_LIMIT:
                return None
            while block := source.read(LOOSE_OBJECT_READ_SIZE):
                compressed_bytes += len(block)
                if compressed_bytes > LOOSE_OBJECT_LIMIT:
                    return None
                remaining = LOOSE_OBJECT_LIMIT + 1 - len(raw)
                raw.extend(decoder.decompress(block, remaining))
                if len(raw) > LOOSE_OBJECT_LIMIT or decoder.unconsumed_tail:
                    return None
        if not decoder.eof or decoder.unused_data:
            return None
        raw = bytes(raw)
        header, body = raw.split(b"\0", 1)
        object_type, declared = header.decode("ascii").split(" ", 1)
        if object_type not in {"blob", "tree", "commit", "tag"} or int(declared) != len(body):
            return None
        algo = "sha256" if oid and len(oid) == 64 else "sha1"
        actual = hashlib.new(algo, raw).hexdigest()
        return {"id": oid or actual, "actual_id": actual, "type": object_type, "size": len(body), "body": body, "valid": oid is None or oid == actual, "storage": "loose"}
    except (OSError, ValueError, zlib.error, UnicodeError):
        return None


def loose_objects(git_dir: Path, limit: int = 50_000,
                  stats: dict[str, int | bool] | None = None) -> Iterable[dict[str, Any]]:
    objects = git_dir / "objects"
    counters = stats if stats is not None else {}
    counters.update({"considered": 0, "parsed": 0, "rejected": 0, "limit_reached": False})
    if not objects.is_dir():
        return
    if objects.is_symlink():
        counters["rejected"] = 1
        return
    prefixes = list(itertools.islice(objects.iterdir(), LOOSE_OBJECT_PREFIX_LIMIT + 1))
    prefix_capped = len(prefixes) > LOOSE_OBJECT_PREFIX_LIMIT
    prefixes = sorted(prefixes[:LOOSE_OBJECT_PREFIX_LIMIT], key=lambda item: item.name)
    entries_seen = 0
    for prefix in prefixes:
        if not re.fullmatch(r"[0-9a-f]{2}", prefix.name):
            continue
        if prefix.is_symlink() or not prefix.is_dir():
            counters["rejected"] = int(counters["rejected"]) + 1
            continue
        remaining = max(0, limit - entries_seen)
        batch = list(itertools.islice(prefix.iterdir(), remaining + 1))
        capped = len(batch) > remaining
        batch = sorted(batch[:remaining], key=lambda item: item.name)
        entries_seen += len(batch)
        for child in batch:
            oid = prefix.name + child.name
            if not OID_RE.fullmatch(oid):
                continue
            if child.is_symlink() or not child.is_file():
                counters["rejected"] = int(counters["rejected"]) + 1
                continue
            counters["considered"] = int(counters["considered"]) + 1
            parsed = parse_loose_object(child, oid)
            if not parsed:
                counters["rejected"] = int(counters["rejected"]) + 1
                continue
            parsed["path"] = str(child)
            counters["parsed"] = int(counters["parsed"]) + 1
            yield parsed
        if capped:
            counters["limit_reached"] = True
            return
    if prefix_capped:
        counters["limit_reached"] = True


def _all_git_objects(git_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    commands: list[dict[str, Any]] = []
    objects: list[dict[str, Any]] = []
    if not shutil.which("git"):
        return objects, commands
    record = _git(git_dir, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize) %(objectsize:disk)"])
    commands.append(record)
    for line in record["stdout"].splitlines():
        fields = line.split()
        if len(fields) >= 3 and OID_RE.fullmatch(fields[0]):
            objects.append({"id": fields[0], "type": fields[1], "size": int(fields[2]), "disk_size": int(fields[3]) if len(fields) > 3 else None, "storage": "git-cat-file", "reachable": None})
    return objects, commands


def _refs(git_dir: Path) -> tuple[list[dict[str, Any]], dict[str, set[str]], dict[str, Any]]:
    rec = _git(git_dir, ["for-each-ref", "--format=%(objectname)%09%(refname)%09%(objecttype)"])
    refs = []
    by_oid: dict[str, set[str]] = {}
    for line in rec["stdout"].splitlines():
        fields = line.split("\t")
        if len(fields) == 3:
            refs.append({"oid": fields[0], "name": fields[1], "type": fields[2]})
            by_oid.setdefault(fields[0], set()).add(fields[1])
    return refs, by_oid, rec


def _commit_metadata(git_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    commands = []
    record = _git(git_dir, ["log", "--all", "--reflog", "--date=iso-strict", "--pretty=format:%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%s%x1e"], timeout=300)
    commands.append(record)
    commits = []
    for row in record["stdout"].split("\x1e"):
        fields = row.strip().split("\x1f")
        if len(fields) == 9:
            commits.append({"id": fields[0], "parents": fields[1].split(), "author": fields[2], "author_email": fields[3], "authored": fields[4], "committer": fields[5], "committer_email": fields[6], "committed": fields[7], "message": fields[8], "reachable": True})
    fsck = _git(git_dir, ["fsck", "--full", "--no-reflogs", "--unreachable"], timeout=300)
    commands.append(fsck)
    unreachable = []
    for line in (fsck["stdout"] + "\n" + fsck["stderr"]).splitlines():
        match = re.search(r"(?:unreachable|dangling) (commit|tree|blob|tag) ([0-9a-f]{40,64})", line)
        if match:
            unreachable.append({"type": match.group(1), "id": match.group(2), "status": "unreachable" if "unreachable" in line else "dangling"})
    known = {item["id"] for item in commits}
    for item in unreachable:
        if item["type"] != "commit" or item["id"] in known:
            continue
        show = _git(git_dir, ["show", "-s", "--date=iso-strict", "--format=%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%s", item["id"]])
        commands.append(show)
        fields = show["stdout"].strip().split("\x1f")
        if len(fields) == 9:
            commits.append({"id": fields[0], "parents": fields[1].split(), "author": fields[2], "author_email": fields[3], "authored": fields[4], "committer": fields[5], "committer_email": fields[6], "committed": fields[7], "message": fields[8], "reachable": False})
    return commits, unreachable + commands


def analyze_repository(repo: dict[str, Any], output: Path, config: ScanConfig, *, max_objects: int = 50_000) -> dict[str, Any]:
    git_dir = Path(repo["git_dir"])
    output.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {**repo, "valid": False, "integrity": "unverified", "head": None, "branch": None, "refs": [], "commits": [], "objects": [], "recovered": [], "findings": [], "commands": [], "warnings": []}
    warning_omitted = 0
    command_omitted = 0

    def warn(message: str) -> None:
        nonlocal warning_omitted
        if message in result["warnings"]:
            return
        if len(result["warnings"]) < MAX_REPOSITORY_WARNINGS:
            result["warnings"].append(message)
        else:
            warning_omitted += 1
        config.warn(message)

    def record_command(record: dict[str, Any], label: str, *, failure_is_gap: bool = False) -> None:
        nonlocal command_omitted
        if len(result["commands"]) < MAX_REPOSITORY_COMMANDS:
            result["commands"].append(_command_summary(record))
        else:
            command_omitted += 1
        timed_out = bool(record.get("timed_out"))
        truncated = bool(record.get("output_truncated"))
        failed = failure_is_gap and not record.get("ok", False)
        if timed_out or truncated or failed:
            reasons = []
            if timed_out:
                reasons.append("timeout")
            if truncated:
                reasons.append("output cap")
            if failed:
                reasons.append("command error")
            warn(f"{label}: inventory or parsing incomplete ({', '.join(reasons)}).")

    head_path = git_dir / "HEAD"
    if head_path.is_file():
        head_text = head_path.read_text("utf-8", "replace").strip()
        result["head"] = head_text
        result["branch"] = head_text.removeprefix("ref: refs/heads/") if head_text.startswith("ref: refs/heads/") else "DETACHED"
    objects, commands = _all_git_objects(git_dir)
    for command in commands:
        record_command(command, "Git object inventory", failure_is_gap=True)
    result["objects"] = objects[:max_objects]
    if len(objects) > max_objects:
        warn(f"Git object inventory capped at {max_objects} of at least {len(objects)} objects.")
    if shutil.which("git"):
        verify = _git(git_dir, ["rev-parse", "--is-bare-repository"])
        record_command(verify, "Git repository validation", failure_is_gap=True)
        result["valid"] = verify["ok"]
        result["integrity"] = "complete" if verify["ok"] else "partial"
        refs, _ref_map, refs_command = _refs(git_dir)
        record_command(refs_command, "Git reference inventory", failure_is_gap=True)
        result["refs"] = refs
        commits, mixed = _commit_metadata(git_dir)
        result["commits"] = commits
        unreachable = [item for item in mixed if "command" not in item]
        for command in (item for item in mixed if "command" in item):
            record_command(
                command,
                "Git commit/unreachable inventory",
                failure_is_gap=True,
            )
        if len(commits) > 10_000:
            warn(f"Commit inventory capped at 10,000 of {len(commits)} commits.")
        unreachable_ids = {item["id"] for item in unreachable}
        for item in result["objects"]:
            item["reachable"] = item["id"] not in unreachable_ids
            item["status"] = next((u["status"] for u in unreachable if u["id"] == item["id"]), "reachable")
        # Every blob is scanned, including packed and unreachable objects. Interesting/old blobs are exported without checkout.
        for item in result["objects"]:
            if item["type"] != "blob":
                continue
            remaining = max(0, config.max_input_bytes - config.bytes_read)
            object_limit = min(16 * 1024 * 1024, remaining)
            if item.get("size", 0) > object_limit:
                warn(f"Blob {item['id']} oltre budget per oggetto/input; contenuto non letto.")
                continue
            data, content = run_binary(["git", f"--git-dir={git_dir}", "cat-file", "blob", item["id"]], timeout=60, max_bytes=object_limit)
            record_command(content, f"Git blob {item['id']} read", failure_is_gap=True)
            if not content["ok"]:
                continue
            config.bytes_read += len(data)
            findings = scan_bytes(data, source=str(git_dir), path=f"git:{item['id']}", module="git", config=config, method="git-object")
            for finding in findings:
                finding.metadata.update({"repository": str(git_dir), "object": item["id"], "object_type": "blob", "reachable": item.get("reachable")})
            result["findings"].extend(findings)
            if findings or not item.get("reachable", True):
                target = output / f"{item['id']}_{safe_name(findings[0].value[:32] if findings else 'unreachable_blob')}.bin"
                target.write_bytes(data)
                result["recovered"].append({"path": str(target), "blob": item["id"], "status": item.get("status", "historical")})
        for commit in commits[:10_000]:
            result["findings"].extend(scan_bytes(commit["message"].encode(), source=str(git_dir), path=f"commit:{commit['id']}", module="git", config=config, method="commit-message"))
            tree = _git(git_dir, ["ls-tree", "-r", "--full-tree", commit["id"]], timeout=120)
            record_command(tree, f"Git tree inventory {commit['id']}", failure_is_gap=True)
            tree_lines = tree["stdout"].splitlines()
            if len(tree_lines) > 100_000:
                warn(f"Tree {commit['id']} capped at 100,000 entries.")
            for line in tree_lines[:100_000]:
                match = re.match(r"(\d+) (\w+) ([0-9a-f]{40,64})\t(.*)", line)
                if not match:
                    continue
                path = match.group(4)
                result["findings"].extend(scan_bytes(path.encode(), source=str(git_dir), path=path, module="git", config=config, method="git-path"))
        # Generic, evidence-backed reconstruction: only when a commit explicitly
        # instructs that a literal phrase must be wrapped in the configured flag format.
        for commit in commits[:10_000]:
            instruction = re.search(r"(?i)wrap\s+(?:this\s+)?(?:phrase|value|string)\s+in\s+(?:the\s+)?flag\s+format\s*:\s*([A-Za-z0-9_+./=-]{3,256})", commit["message"])
            if not instruction:
                continue
            payload = instruction.group(1)
            for prefix in config.prefixes:
                name = prefix[:-1] if prefix.endswith("{") else prefix
                candidate = f"{name}{{{payload}}}"
                result["findings"].append(Finding(
                    module="git", kind="flag_candidate", source=str(git_dir), path=f"commit:{commit['id']}",
                    value=candidate, size=len(candidate), method="explicit-commit-instruction-reconstruction",
                    confidence=0.72, context_before=commit["message"],
                    metadata={"repository": str(git_dir), "commit": commit["id"], "reconstructed": True,
                              "probabilistic": True, "instruction": commit["message"]},
                ))
        # Removed lines are independently scanned, covering flags deleted between versions.
        diff = _git(git_dir, ["log", "--all", "--reflog", "-p", "--format=commit:%H"], timeout=300)
        record_command(diff, "Git removed-line history", failure_is_gap=True)
        removed = "\n".join(line[1:] for line in diff["stdout"].splitlines() if line.startswith("-") and not line.startswith("---"))
        result["findings"].extend(scan_bytes(removed.encode(), source=str(git_dir), path="git:removed-lines", module="git", config=config, method="git-diff-removed"))
    else:
        warn("Git CLI unavailable; refs, commit history, packed objects and removed-line scans were skipped.")
        audit: dict[str, int | bool] = {}
        result["objects"] = []
        for item in loose_objects(git_dir, max_objects, audit):
            result["objects"].append({k: v for k, v in item.items() if k != "body"})
            result["valid"] = result["valid"] or item["valid"]
            result["findings"].extend(scan_bytes(item["body"], source=str(git_dir), path=item["path"], module="git", config=config, method="loose-object-parser"))
        rejected = int(audit.get("rejected", 0))
        capped = bool(audit.get("limit_reached", False))
        if rejected:
            warn(f"{rejected} loose Git objects were malformed or exceeded the per-object budget.")
        if capped:
            warn(f"Loose Git object inventory capped at {max_objects} objects.")
        result["integrity"] = "partial"
    if command_omitted:
        warn(f"Git command log capped at {MAX_REPOSITORY_COMMANDS}; {command_omitted} command summaries omitted.")
    result["command_coverage"] = {
        "stored": len(result["commands"]),
        "omitted": command_omitted,
        "complete": command_omitted == 0,
    }
    if warning_omitted:
        if result["warnings"]:
            warning_omitted += 1  # The final detail is replaced by the omission summary.
        summary = f"Additional repository warnings omitted ({warning_omitted}); warning_coverage contains the count."
        if result["warnings"]:
            result["warnings"][-1] = summary
        else:
            result["warnings"].append(summary)
        result["warning_coverage"] = {"stored": len(result["warnings"]), "omitted": warning_omitted, "complete": False}
    else:
        result["warning_coverage"] = {"stored": len(result["warnings"]), "omitted": 0, "complete": True}
    if result["warnings"] and result["integrity"] == "complete":
        result["integrity"] = "partial"
    return result


def analyze(root: Path, output: Path, config: ScanConfig) -> dict[str, Any]:
    repositories = find_repositories(root)
    results = []
    output.mkdir(parents=True, exist_ok=True)
    for index, repo in enumerate(repositories):
        results.append(analyze_repository(repo, output / f"repo_{index}", config))
    return {"repositories": results, "count": len(results), "findings": [finding for repo in results for finding in repo["findings"]]}
