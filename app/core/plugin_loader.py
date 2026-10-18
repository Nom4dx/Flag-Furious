import json
from pathlib import Path
from app.models.contracts import Manifest
from app.core.security import contained


def discover(directory):
    valid, errors, claimed = {}, [], set()
    for folder in sorted(Path(directory).glob("*")):
        if not folder.is_dir() or folder.name.startswith("_"):
            continue
        try:
            if folder.is_symlink():
                raise ValueError("Symlink plugin non ammessi")
            count = total = 0
            for source in folder.rglob("*"):
                if source.is_symlink():
                    raise ValueError("Symlink interni al plugin non ammessi")
                if source.is_file():
                    count += 1
                    total += source.stat().st_size
                    if count > 10000 or total > 256 * 1024**2:
                        raise ValueError("Plugin troppo grande per il loader locale")
            for name in ("plugin.json", "extensions.json", "output_schema.json"):
                path = contained(folder, folder / name)
                if path.stat().st_size > 1024**2:
                    raise ValueError("Manifest troppo grande")
            manifest = Manifest.model_validate_json((folder / "plugin.json").read_text()).model_dump(
                by_alias=True
            )
            names = [manifest["id"], *manifest.get("aliases", [])]
            if any(not __import__("re").fullmatch(r"[a-z][a-z0-9-]{0,63}", name) for name in names):
                raise ValueError("ID o alias plugin non valido")
            if len(set(names)) != len(names) or claimed.intersection(names):
                raise ValueError("ID o alias plugin duplicato")
            contained(folder, folder / manifest["entrypoint"]).stat()
            if manifest["custom_routes"]:
                contained(folder, folder / manifest["custom_routes"]).stat()
            matchers = json.loads((folder / "extensions.json").read_text())
            schema = json.loads((folder / "output_schema.json").read_text())
            if not isinstance(matchers, dict) or not isinstance(schema.get("sections"), list):
                raise ValueError("Schema plugin non valido")
            from app.core.presentation import validate_mapping

            validate_mapping(schema)
            from jsonschema import Draft202012Validator

            if "json_schema" in matchers:
                Draft202012Validator.check_schema(matchers["json_schema"])
            for key in (
                "extensions",
                "mime_types",
                "magic_bytes",
                "asset_types",
                "content_signatures",
                "regex",
                "keywords",
                "encodings",
                "protocols",
                "content_types",
            ):
                if key in matchers and not isinstance(matchers[key], list):
                    raise ValueError(f"Matcher {key} deve essere una lista")
            import regex

            for pattern in matchers.get("regex", []):
                if len(pattern) > 512:
                    raise ValueError("Regex matcher troppo lunga")
                regex.compile(pattern)
            ids = set()
            for section in schema["sections"]:
                if section["id"] in ids or "type" not in section:
                    raise ValueError("Sezione duplicata o senza type")
                ids.add(section["id"])
            seen_routes = set()
            for endpoint in manifest["endpoints"]:
                route = endpoint.get("path", "")
                if not route.startswith("/") or ".." in route or "{" in route:
                    raise ValueError("Endpoint plugin non valido")
                key = (endpoint.get("method", "GET").upper(), route)
                if key in seen_routes:
                    raise ValueError("Endpoint duplicato")
                if key[0] not in ("GET", "POST"):
                    raise ValueError("Endpoint plugin: metodi supportati GET e POST")
                seen_routes.add(key)
                if not endpoint.get("handler", "").isidentifier():
                    raise ValueError("Handler endpoint non valido")
            valid[manifest["id"]] = {
                "manifest": manifest,
                "matchers": matchers,
                "output_schema": schema,
                "directory": str(folder.resolve()),
                "available": True,
                "warnings": [],
            }
            claimed.update(names)
        except Exception as exc:
            errors.append({"plugin": folder.name, "error": str(exc)})
    return valid, errors
