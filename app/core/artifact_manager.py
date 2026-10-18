import base64
import hashlib
import io
import json
from app.services.store import uid, now


class ArtifactManager:
    def __init__(self, assets, store):
        self.assets, self.store = assets, store

    def register(self, item, parent, plugin_id, job_id=None):
        item = dict(item)
        encoded = item.pop("content_base64", None)
        if encoded is None:
            content = item.pop("content", "")
            kind = item.get("type", "text")
            if kind == "hex":
                data = bytes.fromhex(str(content))
            else:
                data = (
                    content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
                ).encode()
            name = item.get("name", "output.txt")
        else:
            data = base64.b64decode(encoded, validate=True)
            if len(data) > self.assets.settings.byte_budget:
                raise ValueError("Budget artefatto superato")
            kind = "file"
            name = item.get("name", "output.bin")

        # Plugin diversi e job ripetuti estraggono spesso gli stessi byte. Riutilizzare
        # l'asset del caso evita copie inutili e impedisce che una nuova analisi esaurisca
        # il limite degli asset. Il record artifact resta distinto e conserva la nuova
        # provenienza (plugin, job e asset padre).
        digest = hashlib.sha256(data).hexdigest()
        derived = next(
            (
                asset
                for asset in self.store.list("asset", parent["case_id"])
                if asset.get("hashes", {}).get("sha256") == digest
            ),
            None,
        )
        deduplicated = derived is not None
        if derived is None and encoded is None:
            derived = self.assets.ingest(
                parent["case_id"], name, kind=kind, content=content, parent=parent
            )
        elif derived is None:
            derived = self.assets.ingest(
                parent["case_id"], name, stream=io.BytesIO(data), parent=parent
            )
        artifact = {
            "id": uid(),
            "case_id": parent["case_id"],
            "asset_id": derived["id"],
            "parent_id": parent["id"],
            "plugin_id": plugin_id,
            "job_id": job_id,
            "name": derived["name"],
            "size": derived["size"],
            "mime": derived["mime"],
            "hashes": derived["hashes"],
            "sha256": derived.get("hashes", {}).get("sha256"),
            "created_at": now(),
            "offset": item.get("offset"),
            "method": item.get("method", "plugin output"),
            "deduplicated": deduplicated,
            "source_asset_id": item.get("source_asset_id", parent["id"]),
        }
        for key, limit in (
            ("source", 1024),
            ("source_location", 1024),
            ("source_member", 512),
            ("encoding", 64),
            ("origin", 256),
            ("status", 32),
        ):
            value = item.get(key)
            if isinstance(value, str):
                artifact[key] = value[:limit]
        for key in ("source_offset", "confidence"):
            value = item.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                artifact[key] = value
        scope = item.get("source_offset_scope")
        if isinstance(scope, str):
            artifact["source_offset_scope"] = scope[:64]
        self.store.put("artifact", artifact)
        return artifact, derived
