import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def safe_name(name):
    return (
        re.sub(r"[^\w. -]", "_", Path(name.replace("\\", "/")).name, flags=re.UNICODE).strip(". ")[:160]
        or "asset.bin"
    )


def contained(root, path):
    root, path = Path(root).resolve(), Path(path)
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError("Percorso fuori dalla directory consentita")
    return path.resolve()


class Sandbox:
    """No host writable mounts, no network, no elevated capabilities.

    Input is a bounded read-only view, or the complete evidence for declared
    random-access analyzers. Work/tmp are size-limited tmpfs mounts.
    Artifacts leave the namespace exclusively through bounded JSON IPC.
    """

    def __init__(self, settings):
        self.settings = settings
        self.runtime = tempfile.TemporaryDirectory(prefix="forensic-hub-runtime-")
        self.runtime_app = Path(self.runtime.name) / "app"
        shutil.copytree(settings.root / "app", self.runtime_app, ignore=shutil.ignore_patterns("__pycache__"))
        self.runtime_python = Path(self.runtime.name) / "python"
        self.runtime_python.mkdir()
        self.python_paths = []
        for path in sys.path:
            source = Path(path)
            if (
                source.is_dir()
                and source.name in ("site-packages", "dist-packages")
                and not source.resolve().is_relative_to("/usr")
            ):
                name = f"site-{len(self.python_paths)}"
                shutil.copytree(
                    source,
                    self.runtime_python / name,
                    ignore=shutil.ignore_patterns("__pycache__", "playwright", "ruff"),
                )
                self.python_paths.append("/python/" + name)
        self.available = False
        self.reason = "bubblewrap non disponibile"
        if shutil.which("bwrap"):
            try:
                probe = subprocess.run(
                    [
                        "bwrap",
                        "--ro-bind",
                        "/usr",
                        "/usr",
                        "--symlink",
                        "usr/lib",
                        "/lib",
                        "--symlink",
                        "usr/lib64",
                        "/lib64",
                        "--unshare-all",
                        "--die-with-parent",
                        "/usr/bin/true",
                    ],
                    capture_output=True,
                    timeout=5,
                )
                self.available = probe.returncode == 0
                self.reason = probe.stderr.decode(errors="replace")[:500] if not self.available else ""
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.reason = str(exc)

    def run(self, action, asset=None, plugin=None, context=None, cancel=None, reporter=None, pause=None):
        if not self.available:
            raise RuntimeError("Isolamento richiesto: " + self.reason)
        cfg = self.settings
        manifest = plugin["manifest"] if plugin else {}
        if manifest.get("requires_root") or manifest.get("requires_network") or manifest.get("permissions"):
            raise ValueError("Permessi non concessi dalla policy locale")
        context = dict(context or {})
        budget = min(
            context.get("byte_budget", cfg.byte_budget), manifest.get("byte_budget", cfg.byte_budget)
        )
        if not isinstance(budget, int) or budget < 1:
            raise ValueError("Il byte budget deve essere un intero positivo")
        timeout = min(cfg.timeout, manifest.get("timeout", cfg.timeout))
        output_limit = min(manifest.get("output_bytes", cfg.byte_budget), cfg.byte_budget)
        workspace_limit = min(manifest.get("workspace_bytes") or output_limit, cfg.max_workspace_bytes)
        with tempfile.TemporaryDirectory(prefix="forensic-hub-worker-") as tmp:
            payload = {"action": action, "asset": dict(asset or {}), "context": context, "manifest": manifest}
            args = [
                "bwrap",
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--cap-drop",
                "ALL",
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
                "--setenv",
                "HOME",
                "/tmp",
                "--setenv",
                "PYTHONPATH",
                "/hub",
                "--setenv",
                "PYTHONDONTWRITEBYTECODE",
                "1",
                "--setenv",
                "LC_ALL",
                "C.UTF-8",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--size",
                str(workspace_limit),
                "--tmpfs",
                "/work",
                "--size",
                str(16 * 1024**2),
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                str(self.runtime_app),
                "/hub/app",
                "--chdir",
                "/work",
            ]
            if asset and asset.get("path"):
                source = Path(asset["path"])
                # Never expose paths of other evidence or case metadata to plugins.
                input_folder = Path(tmp) / "evidence"
                input_folder.mkdir()
                target = input_folder / safe_name(asset["name"])
                remaining = budget
                full_input = action == "analyze" and manifest.get("input_access") == "random_access"
                if full_input:
                    if not source.is_file() or source.is_symlink() or source.stat().st_size > cfg.max_upload:
                        raise ValueError("Input random-access non valido o oltre il limite upload")
                    # Evidence is deliberately mode 0400. Binding that inode
                    # directly fails while bubblewrap creates an unprivileged
                    # user namespace. A private byte-for-byte staging copy keeps
                    # the original immutable and makes the complete image
                    # readable inside the namespace.
                    shutil.copyfile(source, target)
                    target.chmod(0o444)
                elif asset.get("type") == "directory":
                    target.mkdir()
                    for entry in asset.get("entries", []):
                        relative = Path(entry["relative_path"])
                        if relative.is_absolute() or ".." in relative.parts:
                            raise ValueError("Percorso directory non sicuro")
                        output = target / relative
                        output.parent.mkdir(parents=True, exist_ok=True)
                        with Path(entry["path"]).open("rb") as src, output.open("xb") as dst:
                            while remaining:
                                block = src.read(min(1024**2, remaining))
                                if not block:
                                    break
                                dst.write(block)
                                remaining -= len(block)
                        if remaining <= 0:
                            break
                else:
                    with source.open("rb") as src, target.open("xb") as dst:
                        while remaining:
                            block = src.read(min(1024**2, remaining))
                            if not block:
                                break
                            dst.write(block)
                            remaining -= len(block)
                input_path = "/input/" + safe_name(asset["name"])
                args += ["--ro-bind", str(target), input_path]
                payload["asset"]["path"] = input_path
                payload["asset"]["partial_input"] = not full_input and asset["size"] > budget
                payload["asset"]["visible_bytes"] = (
                    source.stat().st_size if full_input else budget - remaining
                )
                payload["asset"].pop("entries", None)
            # Multi-input extraction connectors may pair a BitLocker image with
            # one or more 66-byte FVEK artifacts produced from RAM. Only these
            # tiny same-case artifacts are staged; no sibling evidence path is
            # exposed to the plugin process.
            staged_companions = []
            companions = payload["context"].get("companion_assets", [])[:32]
            if companions:
                # Bubblewrap does not guarantee that the parent of a file bind
                # target exists.  Create the private mount point before adding
                # individual read-only key candidates.
                args += ["--dir", "/companions"]
            for index, companion in enumerate(companions):
                companion_source = Path(companion.get("path", ""))
                if (
                    companion.get("size") != 66
                    or not companion_source.is_file()
                    or companion_source.is_symlink()
                    or companion_source.stat().st_size != 66
                ):
                    continue
                companion_copy = Path(tmp) / f"companion-{index}.fvek"
                shutil.copyfile(companion_source, companion_copy)
                companion_copy.chmod(0o444)
                companion_path = f"/companions/{index}.fvek"
                args += ["--ro-bind", str(companion_copy), companion_path]
                staged_companions.append({
                    "id": companion.get("id"),
                    "name": companion.get("name"),
                    "size": 66,
                    "path": companion_path,
                })
            payload["context"]["companion_assets"] = staged_companions
            if plugin:
                snapshot = Path(tmp) / "plugin"
                shutil.copytree(
                    plugin["directory"],
                    snapshot,
                    ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"),
                )
                args += ["--ro-bind", str(snapshot), "/plugin"]
                # Password recovery may read only the wordlist files explicitly
                # selected by the local operator. Host paths are never passed to
                # the worker and directories are not mounted wholesale.
                if manifest.get("id") == "bruteforce":
                    brute = payload["context"].get("plugin_options", {}).get("bruteforce", {})
                    selected = brute.get("wordlists", [])
                    roots = [Path(value).expanduser().resolve() for value in brute.get("wordlist_roots", [])]
                    roots += [Path(value).expanduser().resolve() for value in cfg.wordlist_roots]
                    remembered_path = cfg.storage / "wordlist-roots.json"
                    if remembered_path.is_file():
                        roots += [Path(value).expanduser().resolve() for value in json.loads(remembered_path.read_text()).get("roots", [])]
                    roots += [(cfg.root / name).resolve() for name in ("wordlists", "SecLists", "data/wordlists")]
                    mounted = []
                    staged_wordlist_bytes = 0
                    for index, value in enumerate(selected[:32]):
                        source_wordlist = Path(value).expanduser().resolve()
                        if (
                            source_wordlist.is_symlink()
                            or not source_wordlist.is_file()
                            or source_wordlist.suffix.lower() not in {".txt", ".lst", ".dic", ".wordlist"}
                            or not any(source_wordlist.is_relative_to(root) for root in roots if root.is_dir())
                            or source_wordlist.stat().st_size > 256 * 1024**2
                        ):
                            raise ValueError("Wordlist non autorizzata o non valida")
                        staged_wordlist_bytes += source_wordlist.stat().st_size
                        if staged_wordlist_bytes > 512 * 1024**2:
                            raise ValueError("Budget complessivo wordlist superato")
                        staged_wordlist = Path(tmp) / f"wordlist-{index}"
                        shutil.copyfile(source_wordlist, staged_wordlist)
                        staged_wordlist.chmod(0o444)
                        target_wordlist = f"/wordlists/{index}-{safe_name(source_wordlist.name)}"
                        args += ["--ro-bind", str(staged_wordlist), target_wordlist]
                        mounted.append(target_wordlist)
                    brute["wordlists"] = mounted
                    brute["wordlist_roots"] = ["/wordlists"] if mounted else []
            payload["context"].update(byte_budget=budget, output_dir="/work", output_bytes=output_limit)
            payload["limits"] = {
                "memory_mb": min(cfg.memory_mb, manifest.get("memory_mb", cfg.memory_mb)),
                "cpu_seconds": min(timeout, manifest.get("cpu_seconds", timeout)),
                "output_bytes": output_limit,
                "workspace_bytes": workspace_limit,
            }
            for index, path in enumerate(cfg.signature_files if action == "magic" else ()):
                rule_copy = Path(tmp) / f"rule-{index}.json"
                shutil.copyfile(path, rule_copy)
                args += ["--ro-bind", str(rule_copy), f"/rules/{index}.json"]
                payload["context"].setdefault("signature_files", []).append(f"/rules/{index}.json")
            args += [
                "--ro-bind",
                str(self.runtime_python),
                "/python",
                "--setenv",
                "PYTHONPATH",
                ":".join(["/hub", *self.python_paths]),
            ]
            args += [getattr(sys, "_base_executable", sys.executable), "-m", "app.core.worker"]
            proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                try:
                    proc.stdin.write(json.dumps(payload).encode())
                    proc.stdin.close()
                except BrokenPipeError as exc:
                    # Preserve the namespace/bootstrap error instead of replacing
                    # it with the unhelpful host-side EPIPE exception.
                    proc.wait(timeout=2)
                    diagnostic = proc.stderr.read().decode(errors="replace").strip()
                    raise RuntimeError(
                        diagnostic or f"Worker terminato prima di ricevere l'input ({proc.returncode})"
                    ) from exc
                selector = selectors.DefaultSelector()
                selector.register(proc.stdout, selectors.EVENT_READ, "out")
                selector.register(proc.stderr, selectors.EVENT_READ, "err")
                started = time.monotonic()
                pending = b""
                stderr = b""
                total = 0
                result = None
                worker_error = None
                while selector.get_map():
                    if cancel and cancel.is_set():
                        raise InterruptedError("Analisi annullata")
                    if pause and pause.is_set():
                        os.killpg(proc.pid, signal.SIGSTOP)
                        while pause.is_set():
                            if cancel and cancel.is_set():
                                raise InterruptedError("Analisi annullata")
                            time.sleep(0.05)
                        os.killpg(proc.pid, signal.SIGCONT)
                    if time.monotonic() - started > timeout:
                        raise TimeoutError(f"Timeout dopo {timeout}s; risultati parziali nei log")
                    for key, _ in selector.select(0.1):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > output_limit * 2 + 4 * 1024**2:
                            raise ValueError("Budget output IPC superato")
                        if key.data == "err":
                            stderr = (stderr + chunk)[-4096:]
                            continue
                        pending += chunk
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            try:
                                event = json.loads(line)
                            except ValueError:
                                continue
                            if event.get("kind") == "result":
                                result = event["data"]
                            elif event.get("kind") == "worker_error":
                                worker_error = event["data"]
                            elif reporter:
                                reporter(event)
                proc.wait(timeout=2)
                if proc.returncode or result is None:
                    if worker_error:
                        error = (
                            ValueError
                            if worker_error["type"] in ("ValueError", "BadZipFile")
                            else RuntimeError
                        )
                        raise error(worker_error["message"])
                    raise RuntimeError(
                        stderr.decode(errors="replace") or f"Worker terminato ({proc.returncode})"
                    )
                if isinstance(result, dict) and asset and payload["asset"].get("partial_input"):
                    if action == "flags":
                        result.setdefault("metrics", {}).update(
                            visible_bytes=budget,
                            total_bytes=asset["size"],
                            coverage="bounded global flag pre-scan",
                        )
                    else:
                        result.setdefault("warnings", []).append(
                            f"Vista input limitata a {budget} di {asset['size']} byte"
                        )
                    if action not in ("probe", "match", "flags"):
                        result["status"] = "partial"
                return result
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                if "selector" in locals():
                    selector.close()
                for stream in (proc.stdout, proc.stderr):
                    stream.close()
