from __future__ import annotations
import csv
import html
import io
import json
import zipfile
from pathlib import Path
from typing import Any


def bundle(job: dict[str, Any], sections: dict[str, list[dict]], logs: list[dict]) -> dict[str, Any]:
    return {"format": "DiskHunt report v1", "job": {k: v for k, v in job.items() if k not in {"image_path", "original_path", "cancel_requested"}}, **sections, "logs": logs}


def render(report: dict[str, Any], fmt: str) -> tuple[bytes, str, str]:
    if fmt == "json": return json.dumps(report, indent=2, ensure_ascii=False).encode(), "application/json", "report.json"
    if fmt == "markdown":
        job = report["job"]; lines = ["# DiskHunt forensic report", "", f"Job: `{job['id']}`", f"Status: **{job['status']}**", "", "## Hashes", ""]
        for key, value in job.get("stats", {}).get("hashes", {}).items(): lines.append(f"- {key.upper()}: `{value}`")
        lines += ["", "## Flag candidates", ""]
        for flag in report.get("flags", []): lines.append(f"- `{flag['candidate']}` — confidence {flag['confidence']}%, offset {flag['absolute_offset']}")
        lines += ["", "## Recovered artifacts and scan coverage", "",
                  "| Artifact | MIME | Size | SHA-256 | Flag scan | Findings |",
                  "| --- | --- | ---: | --- | --- | ---: |"]
        for item in report.get("artifacts", []):
            name = str(item.get("name_original", item.get("artifact", ""))).replace("|", "\\|").replace("\n", " ")
            lines.append("| {} | {} | {} | `{}` | {} ({} bytes) | {} |".format(
                name, item.get("mime_type", "unknown"), item.get("size", 0),
                item.get("sha256", ""), item.get("flag_scan_status", "not recorded"),
                item.get("flag_scan_bytes", 0), item.get("flag_scan_findings", 0)))
        lines += ["", "## Partitions", "", "```json", json.dumps(report.get("partitions", []), indent=2), "```"]
        return "\n".join(lines).encode(), "text/markdown", "report.md"
    if fmt == "csv":
        output = io.StringIO(); writer = csv.writer(output); writer.writerow(["kind", "candidate/name", "offset", "status", "confidence"])
        for kind in ("flags", "files", "deleted", "carved"):
            for item in report.get(kind, []): writer.writerow([kind, item.get("candidate", item.get("name", "")), item.get("absolute_offset", ""), item.get("status", ""), item.get("confidence", "")])
        return output.getvalue().encode(), "text/csv", "report.csv"
    if fmt == "html":
        payload = html.escape(json.dumps(report, indent=2, ensure_ascii=False))
        doc = f"<!doctype html><html><head><meta charset='utf-8'><title>DiskHunt report</title><style>body{{font:14px system-ui;background:#08111d;color:#d9e6f2;padding:2rem}}pre{{white-space:pre-wrap;background:#101d2d;padding:1rem;border-radius:8px}}</style></head><body><h1>DiskHunt forensic report</h1><pre>{payload}</pre></body></html>"
        return doc.encode(), "text/html", "report.html"
    raise ValueError("unsupported report format")


def create_artifact_zip(report: dict, artifacts: Path) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.json", json.dumps(report, indent=2, ensure_ascii=False))
        if artifacts.exists():
            for path in artifacts.rglob("*"):
                if path.is_file(): archive.write(path, f"artifacts/{path.relative_to(artifacts)}")
    return output.getvalue()
