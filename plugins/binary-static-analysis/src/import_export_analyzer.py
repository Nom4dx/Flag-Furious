"""Cross-format import/export normalization and suspicious API evidence.

Parsers supply raw symbol records. This module adds categories based on names but
does not infer runtime behavior or label a file as malware.
"""

CATEGORIES={
    "network":("socket","connect","internetopen","urlopen","winhttp"),
    "process":("execve","system","createprocess","shellexecute","fork"),
    "persistence":("regsetvalue","createservice","schtasks","launchdaemon"),
    "injection":("writeprocessmemory","createremotethread","ptrace","process_vm_writev"),
    "crypto":("cryptencrypt","evp_encrypt","aes_","chacha","bcrypt"),
    "dynamic_resolution":("getprocaddress","loadlibrary","dlsym","dlopen"),
    "anti_analysis":("isdebuggerpresent","ptrace","cpuid","checkremotedebugger"),
}


def enrich(imports:list[dict])->tuple[list[dict],list[dict]]:
    """Annotate imports and return evidence-backed suspicious findings."""
    rows=[];findings=[]
    for item in imports:
        name=str(item.get("name",""));lower=name.casefold();category=next((key for key,terms in CATEGORIES.items() if any(term in lower for term in terms)),None)
        row={**item,"suspicious_category":item.get("suspicious_category") or category};rows.append(row)
        if row["suspicious_category"]:findings.append({"type":"suspicious_import","severity":"medium","confidence":.78,"evidence":[f"Import {name} associato a {row['suspicious_category']}"],"offset":item.get("offset",0),"section":item.get("source_section") or item.get("library"),"explanation":"Indicatore statico; non dimostra che l’API venga eseguita"})
    return rows,findings
