from __future__ import annotations

import hashlib
import re
import shutil
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from ..scanner import ScanConfig, scan_bytes
from ..models import Finding
from ..util import run, run_binary, safe_name

OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def find_repositories(root: Path) -> list[dict[str, Any]]:
    candidates: dict[Path, str] = {}
    if root.is_dir():
        for path in root.rglob("*"):
            if not path.is_dir() or path.is_symlink():
                continue
            if path.name == ".git":
                candidates[path] = "worktree"
            elif (path / "HEAD").is_file() and (path / "objects").is_dir():
                candidates[path] = "bare" if path.name != ".git" else "worktree"
            elif (path / "objects" / "pack").is_dir() and any((path / "objects" / "pack").glob("*.pack")):
                candidates[path] = "partial"
    return [{"git_dir": str(path), "root": str(path.parent if kind == "worktree" else path), "type": kind} for path, kind in sorted(candidates.items(), key=lambda item: str(item[0]))]


def _git(git_dir: Path, args: list[str], timeout: int = 120) -> dict[str, Any]:
    return run(["git", f"--git-dir={git_dir}", *args], timeout=timeout)


def parse_loose_object(path: Path, oid: str | None = None) -> dict[str, Any] | None:
    try:
        raw = zlib.decompress(path.read_bytes())
        header, body = raw.split(b"\0", 1)
        object_type, declared = header.decode("ascii").split(" ", 1)
        if object_type not in {"blob", "tree", "commit", "tag"} or int(declared) != len(body):
            return None
        algo = "sha256" if oid and len(oid) == 64 else "sha1"
        actual = hashlib.new(algo, raw).hexdigest()
        return {"id": oid or actual, "actual_id": actual, "type": object_type, "size": len(body), "body": body, "valid": oid is None or oid == actual, "storage": "loose"}
    except (OSError, ValueError, zlib.error, UnicodeError):
        return None


def loose_objects(git_dir: Path) -> Iterable[dict[str, Any]]:
    objects = git_dir / "objects"
    if not objects.is_dir():
        return
    for prefix in objects.iterdir():
        if not prefix.is_dir() or not re.fullmatch(r"[0-9a-f]{2}", prefix.name):
            continue
        for child in prefix.iterdir():
            oid = prefix.name + child.name
            if child.is_file() and OID_RE.fullmatch(oid):
                parsed = parse_loose_object(child, oid)
                if parsed:
                    parsed["path"] = str(child)
                    yield parsed


def _all_git_objects(git_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    commands: list[dict[str, Any]] = []
    objects: list[dict[str, Any]] = []
    if not shutil.which("git"):
        return list(loose_objects(git_dir)), commands
    record = _git(git_dir, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize) %(objectsize:disk)"])
    commands.append(record)
    for line in record["stdout"].splitlines():
        fields = line.split()
        if len(fields) >= 3 and OID_RE.fullmatch(fields[0]):
            objects.append({"id": fields[0], "type": fields[1], "size": int(fields[2]), "disk_size": int(fields[3]) if len(fields) > 3 else None, "storage": "git-cat-file", "reachable": None})
    return objects, commands


def _refs(git_dir: Path) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    rec = _git(git_dir, ["for-each-ref", "--format=%(objectname)%09%(refname)%09%(objecttype)"])
    refs = []
    by_oid: dict[str, set[str]] = {}
    for line in rec["stdout"].splitlines():
        fields = line.split("\t")
        if len(fields) == 3:
            refs.append({"oid": fields[0], "name": fields[1], "type": fields[2]})
            by_oid.setdefault(fields[0], set()).add(fields[1])
    return refs, by_oid


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
    head_path = git_dir / "HEAD"
    if head_path.is_file():
        head_text = head_path.read_text("utf-8", "replace").strip()
        result["head"] = head_text
        result["branch"] = head_text.removeprefix("ref: refs/heads/") if head_text.startswith("ref: refs/heads/") else "DETACHED"
    objects, commands = _all_git_objects(git_dir)
    result["commands"].extend(commands)
    result["objects"] = objects[:max_objects]
    if shutil.which("git"):
        verify = _git(git_dir, ["rev-parse", "--is-bare-repository"])
        result["commands"].append(verify)
        result["valid"] = verify["ok"]
        result["integrity"] = "complete" if verify["ok"] else "partial"
        refs, ref_map = _refs(git_dir)
        result["refs"] = refs
        commits, mixed = _commit_metadata(git_dir)
        result["commits"] = commits
        unreachable = [item for item in mixed if "command" not in item]
        result["commands"].extend(item for item in mixed if "command" in item)
        unreachable_ids = {item["id"] for item in unreachable}
        for item in result["objects"]:
            item["reachable"] = item["id"] not in unreachable_ids
            item["status"] = next((u["status"] for u in unreachable if u["id"] == item["id"]), "reachable")
        # Every blob is scanned, including packed and unreachable objects. Interesting/old blobs are exported without checkout.
        for item in result["objects"]:
            if item["type"] != "blob":
                continue
            data, content = run_binary(["git", f"--git-dir={git_dir}", "cat-file", "blob", item["id"]], timeout=60)
            if not content["ok"]:
                continue
            findings = scan_bytes(data, source=str(git_dir), path=f"git:{item['id']}", module="git", config=config, method="git-object")
            for finding in findings:
                finding.metadata.update({"repository": str(git_dir), "object": item["id"], "object_type": "blob", "reachable": item.get("reachable")})
            result["findings"].extend(findings)
            if findings or not item.get("reachable", True):
                target = output / f"{item['id']}_{safe_name(findings[0].value[:32] if findings else 'unreachable_blob')}.bin"
                target.write_bytes(data)
                result["recovered"].append({"path": str(target), "blob": item["id"], "status": item.get("status", "historical")})
        for commit in commits:
            result["findings"].extend(scan_bytes(commit["message"].encode(), source=str(git_dir), path=f"commit:{commit['id']}", module="git", config=config, method="commit-message"))
            tree = _git(git_dir, ["ls-tree", "-r", "--full-tree", commit["id"]], timeout=120)
            for line in tree["stdout"].splitlines():
                match = re.match(r"(\d+) (\w+) ([0-9a-f]{40,64})\t(.*)", line)
                if not match:
                    continue
                path = match.group(4)
                result["findings"].extend(scan_bytes(path.encode(), source=str(git_dir), path=path, module="git", config=config, method="git-path"))
        # Generic, evidence-backed reconstruction: only when a commit explicitly
        # instructs that a literal phrase must be wrapped in the configured flag format.
        for commit in commits:
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
        result["commands"].append({**diff, "stdout": diff["stdout"][:200_000]})
        removed = "\n".join(line[1:] for line in diff["stdout"].splitlines() if line.startswith("-") and not line.startswith("---"))
        result["findings"].extend(scan_bytes(removed.encode(), source=str(git_dir), path="git:removed-lines", module="git", config=config, method="git-diff-removed"))
    else:
        loose = list(loose_objects(git_dir))
        result["objects"] = [{k: v for k, v in item.items() if k != "body"} for item in loose]
        result["valid"] = any(item["valid"] for item in loose)
        result["integrity"] = "partial" if result["valid"] else "unverified"
        for item in loose:
            result["findings"].extend(scan_bytes(item["body"], source=str(git_dir), path=item["path"], module="git", config=config, method="loose-object-parser"))
    return result


def analyze(root: Path, output: Path, config: ScanConfig) -> dict[str, Any]:
    repositories = find_repositories(root)
    results = []
    output.mkdir(parents=True, exist_ok=True)
    for index, repo in enumerate(repositories):
        results.append(analyze_repository(repo, output / f"repo_{index}", config))
    return {"repositories": results, "count": len(results), "findings": [finding for repo in results for finding in repo["findings"]]}
