import html
import json
from app.services.store import now
from app.services.asset_manager import AssetManager


def report(store, case_id):
    case = store.get("case", case_id)
    return {
        "format_version": "1.0",
        "generated_at": now(),
        "case": case,
        "assets": [AssetManager.public(x) for x in store.list("asset", case_id)],
        "jobs": store.list("job", case_id),
        "artifacts": store.list("artifact", case_id),
        "scope": "Risultati limitati ai byte, plugin e trasformazioni effettivamente analizzati; non costituiscono una verifica esaustiva.",
    }


def render_html(value):
    title = html.escape(value["case"]["name"])
    return (
        '<!doctype html><html lang="it"><meta charset="utf-8"><title>'
        + title
        + "</title><style>body{max-width:1000px;margin:40px auto;font:18px Georgia;color:#000;background:#fff}pre{white-space:pre-wrap;overflow-wrap:anywhere;border-top:2px solid;padding:24px 0;font:13px monospace}h1{font-size:48px}</style><h1>Forensic Hub / "
        + title
        + "</h1><p>"
        + html.escape(value["scope"])
        + "</p><pre>"
        + html.escape(json.dumps(value, ensure_ascii=False, indent=2))
        + "</pre></html>"
    )
