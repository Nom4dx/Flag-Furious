"""Global flag search adapter preserving volume and artifact provenance."""

from app.core.flag_detector import search


def hunt(asset:dict,context:dict,source_label:str,parent_volume:str|None=None)->tuple[list[dict],list[str]]:
    """Run the Hub detector over a bounded local file and enrich candidates."""
    try:budget=int(context.get("byte_budget",64*1024*1024))
    except (TypeError,ValueError):budget=64*1024*1024
    budget=max(0,min(budget,64*1024*1024))
    try:max_results=int(context.get("max_flags",100))
    except (TypeError,ValueError):max_results=100
    max_results=max(1,min(max_results,500))
    result=search(asset,{"prefixes":context.get("prefixes",["flag","CTF","picoCTF","BVAULT","SVIUSCG"]),
                         "patterns":context.get("patterns",[]),"byte_budget":budget,"max_results":max_results})
    warnings=list(result.get("warnings",[]))
    if result.get("status")=="partial" and not warnings:
        warnings.append("Ricerca flag parziale: il rilevatore ha raggiunto un limite interno")
    source=Path(asset.get("path",""))
    if source.is_file() and result.get("metrics",{}).get("bytes_read",0)<source.stat().st_size:
        warnings.append(f"Ricerca flag parziale: letti {result.get('metrics',{}).get('bytes_read',0)} di {source.stat().st_size} byte")
    flags=[]
    for item in result.get("flags",[]):
        flags.append({**item,"status":"candidate","source_artifact":source_label,"parent_volume":parent_volume,
                      "decoder_chain":item.get("decoder_chain",[]),"evidence":["Pattern configurato rilevato in dati passivi",f"Origine: {source_label}"],
                      "confidence":item.get("confidence",.82)})
    return flags,warnings
