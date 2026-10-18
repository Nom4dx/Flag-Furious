"""Conservative function and basic-block inference from disassembly rows.

Only entrypoints, symbols and direct call targets create confirmed/candidate
functions. Unknown bytes remain data/unknown; the module never linearly treats the
whole file as executable code.
"""


def analyze(instructions:list[dict],entry_points:list[dict],symbols:list[dict])->dict:
    """Build function candidates, basic blocks and direct call edges."""
    starts={int(item.get("virtual_address",item.get("relative_virtual_address",0))):"function_confirmed" for item in entry_points if item.get("virtual_address") is not None or item.get("relative_virtual_address") is not None}
    for symbol in symbols:
        if symbol.get("type")==2 and symbol.get("value"):starts[int(symbol["value"]) ]="function_confirmed"
    calls=[]
    for row in instructions:
        if row.get("group") in {"call","jump"} and isinstance(row.get("target"),int):
            starts.setdefault(row["target"],"function_candidate" if row["group"]=="call" else "code_region")
            calls.append({"from":row["address"],"to":row["target"],"type":row["group"]})
    functions=[{"id":f"function-{address:x}","address":address,"classification":classification,"reachable":address in starts} for address,classification in sorted(starts.items())]
    terminators={"ret","jmp","b","bx","jr"};blocks=[];current=[]
    for row in instructions:
        current.append(row)
        if row.get("mnemonic") in terminators or row.get("group") in {"jump","return"}:
            blocks.append({"id":f"block-{current[0]['address']:x}","start":current[0]["address"],"end":current[-1]["address"]+len(bytes.fromhex(current[-1]["opcode"])),"instruction_count":len(current)});current=[]
    if current:blocks.append({"id":f"block-{current[0]['address']:x}","start":current[0]["address"],"end":current[-1]["address"]+len(bytes.fromhex(current[-1]["opcode"])),"instruction_count":len(current)})
    return {"functions":functions,"blocks":blocks,"calls":calls}
