"""Connector manifest registry and plugin-to-connector adapter catalog."""

import json
import re
from pathlib import Path


class ConnectorRegistry:
    """Load independent connector manifests and expose extraction plugins as nodes."""

    def __init__(self, root, plugins):
        self.items = {}
        self.errors = []
        self.plugins = plugins
        for folder in sorted(Path(root).glob("*")):
            try:
                if not folder.is_dir() or folder.is_symlink():
                    continue
                data = json.loads((folder / "connector.json").read_text())
                if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", data["id"]):
                    raise ValueError("ID connector non valido")
                if data["plugin_id"] not in plugins:
                    raise ValueError("Plugin associato non disponibile")
                if data["id"] in self.items:
                    raise ValueError("Connector duplicato")
                fields = data.get("configuration", [])
                if not isinstance(fields, list) or not all(isinstance(field, dict) for field in fields):
                    raise ValueError("Configurazione connector non valida")
                field_ids = [field.get("id") for field in fields]
                if None in field_ids or len(field_ids) != len(set(field_ids)):
                    raise ValueError("Configurazione connector non valida")
                if set(data.get("secret_fields", [])) - set(field_ids):
                    raise ValueError("Secret field non dichiarato nella configurazione")
                if data.get("requires_network") or data.get("requires_root"):
                    raise ValueError("I connector locali non possono richiedere rete o root")
                data.update(source="manifest", available=plugins[data["plugin_id"]]["available"])
                self.items[data["id"]] = data
            except Exception as exc:
                self.errors.append({"connector": folder.name, "error": str(exc)})
        extraction_terms = ("extract", "recover", "carv", "derived_asset", "payload")
        for plugin_id, plugin in plugins.items():
            manifest = plugin["manifest"]
            capabilities = [str(value).casefold() for value in manifest.get("capabilities", [])]
            if plugin_id == "bruteforce" or not any(
                term in capability for term in extraction_terms for capability in capabilities
            ):
                continue
            key = "plugin-" + plugin_id
            self.items[key] = {
                "id": key,
                "name": "Estrai con " + manifest["name"],
                "description": manifest.get("description", "Analisi ed estrazione plugin"),
                "plugin_id": plugin_id,
                "mode": "plugin",
                "icon": "fa-puzzle-piece",
                "supported_asset_types": manifest.get("supported_asset_types", []),
                "produces_assets": True,
                "configuration": [],
                "source": "plugin",
                "available": plugin["available"],
            }

    def get(self, id):
        if id not in self.items:
            raise KeyError("connector non trovato")
        return self.items[id]

    def public(self):
        return {"connectors": list(self.items.values()), "errors": self.errors}
