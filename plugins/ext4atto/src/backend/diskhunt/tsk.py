from __future__ import annotations
import re
import shutil
from pathlib import Path
from typing import Callable
from .bounded_process import run_bounded


class TSK:
    def __init__(self, image: Path, logger: Callable[..., None], timeout: int = 120,
                 warn: Callable[[str], None] | None = None,
                 max_output_total: int = 512 * 1024 * 1024):
        self.image = image; self.logger = logger; self.timeout = timeout; self.warn = warn or (lambda _message: None)
        self.max_output_total = max(0, max_output_total); self.output_bytes = 0

    def _remaining_output(self) -> int:
        return max(0, self.max_output_total - self.output_bytes)

    def run(self, command: str, *args: str) -> tuple[int, str]:
        return self._execute(command, list(args), [])

    def _execute(self, command: str, args: list[str], tail: list[str]) -> tuple[int, str]:
        binary = shutil.which(command)
        if not binary:
            message = f"TSK command unavailable: {command}"
            self.warn(message)
            self.logger("WARNING", message)
            return 127, ""
        argv = [binary, *args, str(self.image), *tail]
        printable = " ".join(argv)
        remaining = self._remaining_output()
        if not remaining:
            message = f"{command}: budget cumulativo output TSK esaurito"
            self.warn(message); self.logger("WARNING", message, printable)
            return 124, ""
        proc = run_bounded(argv, timeout=self.timeout, max_stdout=min(8 * 1024 * 1024, remaining))
        self.output_bytes += len(proc["stdout"])
        stdout = proc["stdout"].decode("utf-8", "replace")
        stderr = proc["stderr"].decode("utf-8", "replace")
        if proc["truncated"]:
            message = f"{command}: output troncato ai limiti di processo; risultati parziali"
            self.warn(message)
            self.logger("WARNING", message, printable, (stdout + "\n" + stderr)[:2_000_000])
        elif proc["timed_out"]:
            self.warn(f"{command}: timeout dopo {self.timeout}s; risultati parziali")
            self.logger("ERROR", f"command timed out after {self.timeout}s", printable, stderr)
            return 124, ""
        if proc["returncode"] != 0:
            self.warn(f"{command}: comando terminato con codice {proc['returncode']}; risultati incompleti.")
        if proc["stderr_truncated"]:
            self.warn(f"{command}: stderr limitato")
        else:
            self.logger("INFO" if proc["returncode"] == 0 else "WARNING",
                        f"command exited {proc['returncode']}", printable,
                        (stdout + ("\n" + stderr if stderr else ""))[:2_000_000])
        # Retain parseable output from capped listings; the warning records incomplete coverage.
        return (0 if proc["truncated"] else proc["returncode"]), stdout

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

    def recover(self, sector_offset: int, inode: int, target: Path, deleted: bool = False,
                max_bytes: int = 64 * 1024 * 1024) -> bool:
        binary = shutil.which("icat")
        if not binary: return False
        argv = [binary]
        if deleted: argv.append("-r")
        argv += ["-o", str(sector_offset), str(self.image), str(inode)]
        remaining = self._remaining_output()
        if not remaining:
            self.warn("icat: budget cumulativo output TSK esaurito")
            return False
        try:
            proc = run_bounded(argv, timeout=self.timeout, max_stdout=min(max_bytes, remaining),
                               output_path=target)
        except FileExistsError:
            return False
        if target.exists(): self.output_bytes += target.stat().st_size
        if proc["timed_out"] or proc["truncated"] or proc["returncode"] != 0:
            target.unlink(missing_ok=True)
            message = f"icat inode {inode}: recupero incompleto o oltre limite"
            self.warn(message); self.logger("WARNING", message, " ".join(argv), proc["stderr"].decode("utf-8", "replace"))
            return False
        self.logger("INFO", f"icat inode {inode} recovered {target.stat().st_size} bytes", " ".join(argv), proc["stderr"].decode("utf-8", "replace"))
        return target.stat().st_size > 0

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
        target.parent.mkdir(parents=True, exist_ok=True)
        remaining = self._remaining_output()
        if not remaining:
            self.warn(f"blkls {mode}: budget cumulativo output TSK esaurito")
            return False, True
        limit = min(max_bytes, remaining)
        try:
            proc = run_bounded(argv, timeout=self.timeout, max_stdout=limit,
                               output_path=target)
        except FileExistsError:
            return target.exists() and target.stat().st_size > 0, False
        if proc["timed_out"]:
            self.warn(f"blkls {mode}: timeout, dump parziale")
        if proc["truncated"]:
            self.warn(f"blkls {mode}: dump limitato a {limit} byte")
        if proc["stderr_truncated"]:
            self.warn(f"blkls {mode}: stderr limitato")
        if proc["returncode"] != 0:
            self.warn(f"blkls {mode}: codice di uscita {proc['returncode']}; dump incompleto")
        if not target.exists():
            return False, proc["truncated"] or proc["timed_out"] or proc["returncode"] != 0
        self.output_bytes += target.stat().st_size
        self.logger("INFO" if proc["returncode"] == 0 and not proc["timed_out"] else "WARNING",
                    f"blkls {mode} produced {target.stat().st_size} bytes", " ".join(argv),
                    proc["stderr"].decode("utf-8", "replace"))
        return target.stat().st_size > 0, proc["truncated"] or proc["timed_out"] or proc["returncode"] != 0

    def search_strings(self, patterns) -> list[dict] | None:
        """Stream srch_strings output, retaining matching evidence without buffering all strings."""
        binary = shutil.which("srch_strings")
        if not binary: return None
        from .scanner import scan_bytes
        argv = [binary, "-a", "-t", "d", str(self.image)]; found = []; evidence = []
        remaining = self._remaining_output()
        if not remaining:
            self.warn("srch_strings: budget cumulativo output TSK esaurito")
            return []
        proc = run_bounded(argv, timeout=self.timeout, max_stdout=min(64 * 1024 * 1024, remaining))
        self.output_bytes += len(proc["stdout"])
        if proc["truncated"] or proc["timed_out"]:
            self.warn("srch_strings: output o tempo limitato; ricerca parziale")
        if proc["returncode"] != 0:
            self.warn(f"srch_strings: codice di uscita {proc['returncode']}; ricerca incompleta.")
        for line in proc["stdout"].decode("utf-8", "replace").splitlines():
            match = re.match(r"\s*(\d+)\s+(.*)", line.rstrip("\n"))
            if not match: continue
            offset, value = int(match.group(1)), match.group(2).encode("utf-8", "replace")
            matches = scan_bytes(value, offset, patterns, source="srch_strings", method="raw")
            if matches:
                found.extend(matches[:max(0, 10_000-len(found))])
                if len(evidence) < 500: evidence.append(line.rstrip())
                if len(found) >= 10_000:
                    self.warn("srch_strings: finding limit 10000 raggiunto")
                    break
        self.logger("INFO" if proc["returncode"] == 0 else "WARNING",
                    f"srch_strings found {len(found)} flag candidates", " ".join(argv),
                    ("\n".join(evidence) + proc["stderr"].decode("utf-8", "replace"))[:2_000_000])
        return found
