"""Worker entrypoint. This module is invoked only inside a bubblewrap namespace."""

import base64
import importlib.util
import inspect
import json
import resource
import sys
import types
from pathlib import Path


def emit(kind, data):
    print(json.dumps({"kind": kind, "data": data}, default=str), flush=True)


class Reporter:
    def log(self, message, level="info", command=None):
        emit("log", {"message": str(message), "level": level, "command": command})

    def phase(self, name, **data):
        emit("phase", {"label": name, **data})

    def partial(self, result):
        emit("partial", result)

    def visualization(self, value):
        emit("visualization", value)


def load_plugin(manifest):
    path = (Path("/plugin") / manifest["entrypoint"]).resolve()
    if not path.is_relative_to("/plugin"):
        raise ValueError("Invalid entrypoint")
    package = types.ModuleType("hub_plugin")
    package.__path__ = ["/plugin"]
    sys.modules["hub_plugin"] = package
    sys.path[:0] = ["/plugin", "/plugin/src", "/plugin/src/backend"]
    spec = importlib.util.spec_from_file_location("hub_plugin.entrypoint", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return getattr(module, manifest["class"])()


def pack_files(result, context):
    total = 0
    for key in ("artifacts", "derived_assets"):
        for item in result.get(key, []):
            if "path" not in item:
                continue
            path = Path(item.pop("path"))
            if path.is_symlink() or not path.resolve().is_relative_to("/work") or not path.is_file():
                raise ValueError("Output must be a regular file inside /work")
            total += path.stat().st_size
            if total > context["output_bytes"]:
                raise ValueError("Output byte budget exhausted")
            item["name"] = item.get("name", path.name)
            item["content_base64"] = base64.b64encode(path.read_bytes()).decode()
    return result


def main():
    request = json.load(sys.stdin)
    limits = request["limits"]
    resource.setrlimit(resource.RLIMIT_AS, (limits["memory_mb"] * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits.get("workspace_bytes", limits["output_bytes"]),) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    asset, context, action = request["asset"], request["context"], request["action"]
    reporter = Reporter()

    # Audit every legacy CLI call without changing the preserved tool sources.
    def audit(name, args):
        if name == "subprocess.Popen":
            reporter.log("Esecuzione subprocess", command=args[1])

    sys.addaudithook(audit)
    if action in ("magic", "repair"):
        from app.core.magic_wrapper import analyze, repair

        result = analyze(asset, context, reporter) if action == "magic" else repair(asset, context)
    elif action == "flags":
        from app.core.flag_detector import search

        result = search(asset, context)
    else:
        plugin = load_plugin(request["manifest"])
        try:
            if action == "probe":
                result = {"valid": True}
            elif action == "match":
                result = plugin.can_handle(asset, context)
            elif action == "route":
                route = context["endpoint"]
                if request["manifest"].get("custom_routes"):
                    path = (Path("/plugin") / request["manifest"]["custom_routes"]).resolve()
                    if not path.is_relative_to("/plugin"):
                        raise ValueError("Invalid custom routes path")
                    spec = importlib.util.spec_from_file_location("hub_plugin.routes", path)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[spec.name] = module
                    spec.loader.exec_module(module)
                    result = getattr(module, route["handler"])(context.get("request", {}), context)
                else:
                    result = getattr(plugin, route["handler"])(context.get("request", {}), context)
            else:
                validation = plugin.validate(asset, context)
                if not validation.get("valid"):
                    raise ValueError(validation.get("reason", "Asset non valido"))
                result = plugin.analyze(asset, context, reporter)
                if inspect.isgenerator(result):
                    final = {}
                    for part in result:
                        for key, value in part.items():
                            if isinstance(value, list):
                                final.setdefault(key, []).extend(value)
                            else:
                                final[key] = value
                        reporter.partial(final)
                    result = final
                result = result or {}
                for key, value in [
                    ("artifacts", plugin.extract_artifacts(asset, context, reporter)),
                    ("derived_assets", plugin.create_assets(asset, context, reporter)),
                    ("visualizations", plugin.create_visualizations(result, context)),
                    ("flags", plugin.search_flags(result, context)),
                ]:
                    result.setdefault(key, []).extend(value)
        finally:
            plugin.cleanup(context)
    if isinstance(result, dict):
        result = pack_files(result, context)
    emit("result", result)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        emit("worker_error", {"type": type(exc).__name__, "message": str(exc)})
        sys.exit(1)
