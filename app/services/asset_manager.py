import io
import json
from app.core.asset_detector import detect
from app.core.hashing import calculate_hashes, ALGORITHMS, find_hash_matches
from app.core.security import safe_name
from app.services.store import uid, now


class AssetManager:
    def __init__(self, settings, store, sandbox):
        self.settings, self.store, self.sandbox = settings, store, sandbox

    def ingest(
        self,
        case_id,
        name,
        kind="file",
        stream=None,
        content=None,
        parent=None,
        metadata=None,
        expected_hash=None,
    ):
        with self.store.lock:
            self.store.get("case", case_id)
            asset_count, used = self.store.asset_usage(case_id)
            if asset_count >= self.settings.max_assets:
                raise ValueError("Limite asset del caso raggiunto")
            id = uid()
            folder = self.settings.storage / "cases" / case_id / "evidence" / id
            folder.mkdir(parents=True)
            name = safe_name(name)
            path = folder / name
            if stream is None:
                if kind == "hex":
                    data = bytes.fromhex(str(content))
                    content = data.hex()
                else:
                    data = (
                        content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
                    ).encode()
                stream = io.BytesIO(data)
            try:
                size = 0
                with path.open("xb") as output:
                    while block := stream.read(1024**2):
                        size += len(block)
                        if size > self.settings.max_upload or used + size > self.settings.max_case_bytes:
                            raise ValueError("Limite spazio caso o upload superato")
                        output.write(block)
                path.chmod(0o400)
                hashes = calculate_hashes(path, ALGORITHMS)
                with path.open("rb") as handle:
                    sample = handle.read(65536)
                asset = {
                    "id": id,
                    "case_id": case_id,
                    "name": name,
                    "type": kind,
                    "size": size,
                    "path": str(path),
                    "created_at": now(),
                    "parent_id": parent["id"] if parent else None,
                    "depth": parent["depth"] + 1 if parent else 0,
                    "hashes": hashes.digests,
                    "unsupported_hashes": list(hashes.unsupported),
                    **detect(name, kind, sample),
                }
                asset["metadata"].update(metadata or {})
                if kind != "file":
                    asset["content"] = content
                if expected_hash:
                    asset["hash_matches"] = list(find_hash_matches(expected_hash, hashes.digests))
                if kind == "file":
                    try:
                        asset["triage"] = self.sandbox.run("magic", asset)
                        triage = asset["triage"]
                        if triage.get("format"):
                            asset["content_signatures"].extend(
                                s["name"] for s in triage.get("structures", [])
                            )
                            asset["mime"] = triage["detected_mime"]
                    except Exception as exc:
                        asset["triage"] = {
                            "status": "partial",
                            "summary": "Identificazione limitata",
                            "warnings": [str(exc)],
                            "repair_available": False,
                        }
                return self.store.put("asset", asset)
            except Exception:
                import shutil

                shutil.rmtree(folder)
                raise

    @staticmethod
    def public(asset):
        return {k: v for k, v in asset.items() if k not in ("path", "sample", "header_hex", "entries")}
