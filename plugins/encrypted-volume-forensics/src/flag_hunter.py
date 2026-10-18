"""Global flag search adapter preserving volume and artifact provenance."""

from app.core.flag_detector import search


def hunt(asset:dict,context:dict,source_label:str,parent_volume:str|None=None)->tuple[list[dict],list[str]]:
    """Run the Hub detector over a bounded local file and enrich candidates."""
    result=search(asset,{"prefixes":context.get("prefixes",["flag","CTF","picoCTF","BVAULT","SVIUSCG"]),
                         "patterns":context.get("patterns",[]),"byte_budget":min(int(context.get("byte_budget",64*1024*1024)),64*1024*1024),
                         "max_results":min(int(context.get("max_flags",100)),500)})
    flags=[]
    for item in result.get("flags",[]):
        flags.append({**item,"status":"candidate","source_artifact":source_label,"parent_volume":parent_volume,
                      "decoder_chain":item.get("decoder_chain",[]),"evidence":["Pattern configurato rilevato in dati passivi",f"Origine: {source_label}"],
                      "confidence":item.get("confidence",.82)})
    return flags,result.get("warnings",[])
