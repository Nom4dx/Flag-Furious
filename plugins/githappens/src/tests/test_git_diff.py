import subprocess
from pathlib import Path

from picup_web.modules.git_forensics import analyze, find_repositories, parse_loose_object
from picup_web.modules.reference_diff import analyze as diff_analyze
from picup_web.scanner import ScanConfig


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, stdout=subprocess.PIPE, text=True).stdout.strip()


def test_unreachable_git_blob_is_recovered(tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    git(repo, "init", "-q"); git(repo, "config", "user.name", "Fixture"); git(repo, "config", "user.email", "fixture@example.test")
    (repo / "readme.txt").write_text("clean\n"); git(repo, "add", "."); git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "removed.txt").write_text("picoCTF{unreachable_blob_fixture}\n"); git(repo, "add", "."); git(repo, "commit", "-qm", "temporary secret")
    secret_commit = git(repo, "rev-parse", "HEAD")
    git(repo, "reset", "--hard", "-q", base)
    # Remove the reflog reference while retaining the loose objects.
    git(repo, "reflog", "expire", "--expire=now", "--expire-unreachable=now", "--all")
    out = tmp_path / "out"
    result = analyze(repo, out, ScanConfig())
    values = [f.value for f in result["findings"]]
    assert "picoCTF{unreachable_blob_fixture}" in values
    assert result["repositories"][0]["valid"] is True
    assert any(not item.get("reachable", True) for item in result["repositories"][0]["objects"])


def test_reference_diff_scans_removed_lines(tmp_path):
    before = tmp_path / "before"; after = tmp_path / "after"; before.mkdir(); after.mkdir()
    (before / "same.txt").write_text("one\nflag{removed_only}\nthree\n"); (after / "same.txt").write_text("one\nthree\n")
    result = diff_analyze(before, after, ScanConfig())
    assert any(x.value == "flag{removed_only}" and x.method.endswith("removed-lines:raw") for x in result["findings"])
    assert result["differences"][0]["type"] == "modified"
