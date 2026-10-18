import importlib.util
import shutil
import regex
import threading
from collections import OrderedDict
from jsonschema import Draft202012Validator
from app.core.plugin_loader import discover


class PluginRegistry:
    def __init__(self, settings, sandbox):
        self.sandbox = sandbox
        self._matcher_cache = OrderedDict()
        self._matcher_cache_lock = threading.Lock()
        self._matcher_cache_limit = 4096
        self.plugins, self.errors = discover(settings.plugins)
        self.aliases = {
            alias: plugin_id
            for plugin_id, plugin in self.plugins.items()
            for alias in plugin["manifest"].get("aliases", [])
        }
        for id, plugin in self.plugins.items():
            manifest = plugin["manifest"]
            try:
                for name in manifest["python_dependencies"]:
                    if importlib.util.find_spec(name) is None:
                        raise ValueError(f"Dipendenza Python mancante: {name}")
                for binary in manifest["binaries"]:
                    if not shutil.which(binary):
                        raise ValueError(f"Binario mancante: {binary}")
                for binary in manifest["optional_binaries"]:
                    if not shutil.which(binary):
                        plugin["warnings"].append(f"Funzione opzionale non disponibile: {binary}")
                self.order([id])
                self.sandbox.run("probe", plugin=plugin)
            except Exception as exc:
                plugin["available"] = False
                plugin["error"] = str(exc)
                self.errors.append({"plugin": id, "error": str(exc)})

    def order(self, selected):
        selected = [self.resolve_id(value) for value in selected]
        ordered, visiting = [], set()

        def visit(id):
            if id in visiting:
                raise ValueError("Ciclo dipendenze plugin")
            if id in ordered:
                return
            if id not in self.plugins:
                raise ValueError(f"Plugin dipendente mancante: {id}")
            visiting.add(id)
            for dependency in self.plugins[id]["manifest"]["dependencies"]:
                visit(dependency)
            visiting.remove(id)
            ordered.append(id)

        for id in selected:
            visit(id)
        return ordered

    def resolve_id(self, value):
        """Resolve a declared compatibility alias to its canonical plugin ID."""
        return self.aliases.get(value, value)

    def public(self, plugin):
        return {k: v for k, v in plugin.items() if k != "directory"}

    def compatible(self, asset, include_connectors=False):
        """Rank analyzers for an asset, hiding connector-only services by default."""
        results = []
        text = asset.get("sample", "")
        header = bytes.fromhex(asset.get("header_hex", ""))
        for id, plugin in self.plugins.items():
            m, rules = plugin["manifest"], plugin["matchers"]
            if m.get("activation") == "connector_only" and not include_connectors:
                continue
            supported = m["supported_asset_types"]
            if (
                supported
                and "*" not in supported
                and not set(supported).intersection([asset["type"], *asset.get("detected_types", [])])
            ):
                continue
            reasons = []
            if asset.get("extension") in rules.get("extensions", []):
                reasons.append("Estensione dichiarata")
            if asset.get("mime") in rules.get("mime_types", []):
                reasons.append("MIME compatibile")
            if asset["type"] in rules.get("asset_types", []):
                reasons.append("Tipo asset compatibile")
            for signature in rules.get("magic_bytes", []):
                try:
                    pattern = signature if isinstance(signature, str) else signature["pattern"]
                    offset = 0 if isinstance(signature, str) else signature.get("offset", 0)
                    if header[offset:].startswith(bytes.fromhex(pattern)):
                        reasons.append(f"Header riconosciuto a offset {offset}")
                except (ValueError, TypeError):
                    continue
            if any(word.casefold() in text.casefold() for word in rules.get("keywords", [])):
                reasons.append("Keyword nel contenuto")
            if any(
                signature in asset.get("content_signatures", [])
                for signature in rules.get("content_signatures", [])
            ):
                reasons.append("Struttura interna riconosciuta")
            if rules.get("json_schema"):
                if Draft202012Validator(rules["json_schema"]).is_valid(asset.get("content")):
                    reasons.append("Schema JSON compatibile")
            for pattern in rules.get("regex", []):
                try:
                    if regex.search(pattern, text, timeout=0.05):
                        reasons.append("Regex sul contenuto")
                except (TimeoutError, regex.error):
                    continue
            for key in ("encoding", "protocol", "content_type"):
                if asset.get("metadata", {}).get(key) in rules.get(key + "s", []):
                    reasons.append(key + " compatibile")
            if rules.get("attributes") and all(
                asset.get("metadata", {}).get(k) == v for k, v in rules["attributes"].items()
            ):
                reasons.append("Attributi compatibili")
            if not reasons and rules and not rules.get("custom_matcher"):
                continue
            decision = {
                "compatible": True,
                "score": min(0.95, 0.35 + len(reasons) * 0.18),
                "reasons": reasons or ["Tipo asset dichiarato"],
            }
            if plugin["available"]:
                key = (id, asset["id"])
                with self._matcher_cache_lock:
                    custom = self._matcher_cache.get(key)
                    if custom is not None:
                        self._matcher_cache.move_to_end(key)
                if custom is None:
                    try:
                        custom = self.sandbox.run("match", asset, plugin, context={"byte_budget": 65536})
                    except Exception as exc:
                        custom = {"compatible": False, "error": str(exc)}
                    with self._matcher_cache_lock:
                        self._matcher_cache[key] = custom
                        self._matcher_cache.move_to_end(key)
                        while len(self._matcher_cache) > self._matcher_cache_limit:
                            self._matcher_cache.popitem(last=False)
                if not custom.get("compatible"):
                    if custom.get("error"):
                        decision.update(compatible=False, error=custom["error"])
                    else:
                        continue
                else:
                    decision["score"] = max(0, min(1, float(custom.get("score", decision["score"]))))
                    decision["reasons"] += custom.get("reasons", [])
            results.append({"plugin_id": id, "name": m["name"], "available": plugin["available"], **decision})
        return sorted(results, key=lambda x: -x["score"])
