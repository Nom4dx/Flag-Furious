"""Passive hidden-content analysis for PDF, Office, ODF, EPUB, HTML and RTF.

The parser searches style/state/revision/comment evidence and never renders
active documents, resolves external links, executes macros, formulas, DDE,
JavaScript or PDF actions.
"""

from __future__ import annotations

import io
import re
import zipfile
from xml.etree import ElementTree


def analyze(data: bytes, detected_formats: set[str], source_file: str, max_members: int = 512, max_member_bytes: int = 16*1024*1024) -> dict:
    """Inspect document syntax and ZIP-based office members within strict caps.

    Output contains hidden text, comments, revisions, hidden sheets/slides,
    embedded object inventory and passive active-content warnings.
    """
    findings=[];items=[];embedded=[];warnings=[]
    if "pdf" in detected_formats or data.startswith(b"%PDF-"):
        text=data.decode("latin1","replace")
        patterns={
            "pdf_invisible_text":r"(?s)(?:1\s+1\s+1\s+rg|/CA\s+0(?:\.0+)?|\bTr\s+3\b).*?(?:Tj|TJ)",
            "pdf_off_page_text":r"(?s)(?:-\d{4,}|\d{6,})\s+(?:-\d{4,}|\d{6,})\s+Td.*?(?:Tj|TJ)",
            "pdf_attachment":r"/(?:EmbeddedFile|Filespec)\b",
            "pdf_active_content":r"/(?:JavaScript|JS|Launch|OpenAction)\b",
        }
        for kind,pattern in patterns.items():
            for match in re.finditer(pattern,text):findings.append({"type":kind,"offset":match.start(),"offset_scope":"input","length":match.end()-match.start(),"confidence":.82 if kind!="pdf_off_page_text" else .62,"status":"detected","evidence":["token PDF statico"]})
        items.append({"type":"pdf_structure","eof_count":data.count(b"%%EOF"),"objects":len(re.findall(rb"\d+\s+\d+\s+obj\b",data)),"streams":data.count(b"stream"),"source_file":source_file})
    is_zip=data.startswith((b"PK\x03\x04",b"PK\x05\x06"))
    if is_zip:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos=archive.infolist()[:max_members];names={x.filename for x in infos}
                family="OOXML" if "[Content_Types].xml" in names else "ODF" if "META-INF/manifest.xml" in names else "EPUB" if "META-INF/container.xml" in names else "ZIP"
                items.append({"type":"document_container","family":family,"members":len(infos),"source_file":source_file})
                for info in infos:
                    lower=info.filename.lower()
                    if info.file_size>max_member_bytes or info.is_dir():continue
                    if not lower.endswith((".xml",".rels",".txt",".html",".htm",".css",".rtf")) and not any(x in lower for x in ("embeddings/","media/","vbaproject")):continue
                    try:raw=archive.read(info)
                    except (RuntimeError,zipfile.BadZipFile) as exc:warnings.append(f"{info.filename}: {exc}");continue
                    text=raw.decode("utf-8","replace")
                    indicators={
                        "office_hidden_or_veryhidden":r'(?i)(?:state|show)="(?:hidden|veryHidden|0)"',
                        "office_revision":r"<(?:w:ins|w:del)\b",
                        "office_comments":r"<(?:w:comment|comment)\b",
                        "office_hidden_text":r'(?i)(?:w:vanish|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)',
                        "office_external_relation":r'(?i)TargetMode="External"',
                    }
                    for kind,pattern in indicators.items():
                        for match in re.finditer(pattern,text):findings.append({"type":kind,"internal_path":info.filename,"offset":None,"offset_scope":"archive_member","internal_offset":match.start(),"internal_offset_unit":"unicode_codepoint","source_offset":info.header_offset,"source_offset_scope":"input","source_offset_role":"archive_member_header","length":len(match.group()),"confidence":.9 if "external" not in kind else .75,"status":"detected","evidence":["XML interno al container"]})
                    if any(x in lower for x in ("embeddings/","vbaproject","media/")):embedded.append({"internal_path":info.filename,"offset":info.header_offset,"offset_scope":"input","size":info.file_size,"status":"detected","active":lower.endswith(("vbaProject.bin".lower(),".js",".exe"))})
        except zipfile.BadZipFile as exc:warnings.append(f"Container documento non valido: {exc}")
    decoded=data.decode("utf-8","replace")
    if decoded.lstrip().lower().startswith(("<html","<!doctype html")):
        html_pattern=rb"(?is)(?:<!--(.*?)-->|<(?:[^>]+)(?:hidden|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^>]*>(.*?)</[^>]+>)"
        for match in re.finditer(html_pattern,data):findings.append({"type":"html_hidden_content","offset":match.start(),"offset_scope":"input","length":match.end()-match.start(),"text":next((x.decode("utf-8","replace") for x in match.groups() if x),"")[:4096],"confidence":.82,"status":"detected"})
    if data.startswith(b"{\\rtf"):
        for match in re.finditer(rb"\\v\b.*?(?:\\v0|})",data,re.S):findings.append({"type":"rtf_hidden_text","offset":match.start(),"offset_scope":"input","length":len(match.group()),"confidence":.9,"status":"detected"})
    return {"items":items,"findings":findings,"embedded":embedded,"warnings":warnings}
