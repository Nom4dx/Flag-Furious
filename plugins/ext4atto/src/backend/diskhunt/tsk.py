from __future__ import annotations
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable


class TSK:
    def __init__(self, image: Path, logger: Callable[..., None], timeout: int = 120):
        self.image = image; self.logger = logger; self.timeout = timeout

    def run(self, command: str, *args: str) -> tuple[int, str]:
        return self._execute(command, list(args), [])

    def _execute(self, command: str, args: list[str], tail: list[str]) -> tuple[int, str]:
        binary = shutil.which(command)
        if not binary:
            self.logger("WARNING", f"TSK command unavailable: {command}")
            return 127, ""
        argv = [binary, *args, str(self.image), *tail]
        printable = " ".join(argv)
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=self.timeout,
                                  env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
            raw = (proc.stdout + ("\n" + proc.stderr if proc.stderr else ""))[:2_000_000]
            self.logger("INFO" if proc.returncode == 0 else "WARNING", f"command exited {proc.returncode}", printable, raw)
            return proc.returncode, proc.stdout
        except subprocess.TimeoutExpired:
            self.logger("ERROR", f"command timed out after {self.timeout}s", printable, "")
            return 124, ""

    def filesystem_stats(self, sector_offset: int) -> str:
        return self.run("fsstat", "-o", str(sector_offset))[1]

    def image_triage(self) -> None:
        self.run("img_stat")
        self.run("mmls")
        self.run("mmstat")

    def list_files(self, sector_offset: int, deleted_only: bool = False) -> list[dict]:
        args = ["-r", "-p", "-l", "-o", str(sector_offset)]
        if deleted_only: args.insert(0, "-d")
        code, output = self.run("fls", *args)
        files = []
        if code: return files
        for line in output.splitlines():
            # long format: type inode name mtime atime ctime crtime size uid gid
            fields = line.split("\t")
            if len(fields) < 3: continue
            match = re.match(r"(?P<type>\S+)\s+(?P<deleted>\*)?\s*(?P<inode>\d+)(?:-\d+-\d+)?:", fields[0])
            if not match: continue
            name = fields[1].replace(" (deleted)", "")
            deleted = bool(match.group("deleted"))
            status = "ORPHAN" if name == "$OrphanFiles" else "RECOVERABLE" if deleted else "ALLOCATED"
            timestamps = {key: fields[index] if len(fields) > index else "" for key, index in {"mtime":2,"atime":3,"ctime":4,"crtime":5}.items()}
            files.append({"inode": int(match.group("inode")), "name": Path(name).name, "original_path": name, "type": match.group("type"),
                          "allocated": not deleted, "deleted": deleted,
                          "size": int(fields[6]) if len(fields) > 6 and fields[6].isdigit() else 0,
                          "status": status, **timestamps})
        return files

    def recover(self, sector_offset: int, inode: int, target: Path, deleted: bool = False) -> bool:
        binary = shutil.which("icat")
        if not binary: return False
        argv = [binary]
        if deleted: argv.append("-r")
        argv += ["-o", str(sector_offset), str(self.image), str(inode)]
        try:
            with target.open("xb") as output:
                proc = subprocess.run(argv, stdout=output, stderr=subprocess.PIPE, timeout=self.timeout)
            self.logger("INFO" if proc.returncode == 0 else "WARNING", f"icat inode {inode} exited {proc.returncode}", " ".join(argv), proc.stderr.decode("utf-8", "replace"))
            return proc.returncode == 0 and target.stat().st_size > 0
        except (subprocess.TimeoutExpired, FileExistsError):
            return False

    def inode_stats(self, sector_offset: int, inode: int) -> str:
        return self._execute("istat", ["-o", str(sector_offset)], [str(inode)])[1]

    def list_unallocated_inodes(self, sector_offset: int) -> str:
        return self.run("ils", "-e", "-o", str(sector_offset))[1]

    def journal_listing(self, sector_offset: int) -> str:
        return self.run("jls", "-o", str(sector_offset))[1]

    def find_name(self, sector_offset: int, inode: int) -> str:
        return self._execute("ffind", ["-o", str(sector_offset)], [str(inode)])[1].strip()

    def block_stats(self, sector_offset: int, block: int) -> str:
        return self._execute("blkstat", ["-o", str(sector_offset)], [str(block)])[1]

    def dump_blocks(self, sector_offset: int, target: Path, mode: str = "unallocated", max_bytes: int = 64 * 1024 * 1024) -> tuple[bool, bool]:
        binary = shutil.which("blkls")
        if not binary: return False, False
        flag = "-s" if mode == "slack" else "-A"
        argv = [binary, flag, "-o", str(sector_offset), str(self.image)]
        target.parent.mkdir(parents=True, exist_ok=True); written = 0; truncated = False
        try:
            with target.open("xb") as output:
                proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                assert proc.stdout is not None
                while block := proc.stdout.read(min(1024 * 1024, max_bytes - written + 1)):
                    if written + len(block) > max_bytes:
                        output.write(block[:max_bytes-written]); truncated = True; proc.terminate(); break
                    output.write(block); written += len(block)
                _, stderr = proc.communicate(timeout=10)
            self.logger("INFO" if proc.returncode in {0, -15} else "WARNING", f"blkls {mode} produced {target.stat().st_size} bytes", " ".join(argv), stderr.decode("utf-8", "replace"))
            return target.stat().st_size > 0, truncated
        except (subprocess.TimeoutExpired, FileExistsError) as exc:
            self.logger("WARNING", f"blkls {mode} failed: {exc}", " ".join(argv), "")
            return target.exists() and target.stat().st_size > 0, truncated

    def search_strings(self, patterns) -> list[dict] | None:
        """Stream srch_strings output, retaining matching evidence without buffering all strings."""
        binary = shutil.which("srch_strings")
        if not binary: return None
        from .scanner import scan_bytes
        argv = [binary, "-a", "-t", "d", str(self.image)]; found = []; evidence = []
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
            assert proc.stdout is not None
            for line in proc.stdout:
                match = re.match(r"\s*(\d+)\s+(.*)", line.rstrip("\n"))
                if not match: continue
                offset, value = int(match.group(1)), match.group(2).encode("utf-8", "replace")
                matches = scan_bytes(value, offset, patterns, source="srch_strings", method="raw")
                if matches:
                    found.extend(matches)
                    if len(evidence) < 500: evidence.append(line.rstrip())
            _, stderr = proc.communicate(timeout=self.timeout)
            self.logger("INFO" if proc.returncode == 0 else "WARNING", f"srch_strings found {len(found)} flag candidates", " ".join(argv), "\n".join(evidence) + stderr)
        except subprocess.TimeoutExpired:
            proc.kill(); self.logger("WARNING", "srch_strings timed out", " ".join(argv), "")
        return found
