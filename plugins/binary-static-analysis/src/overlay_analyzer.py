"""Logical-end and unreferenced-region analysis."""


def analyze(physical_size:int,primary:dict|None,regions:list[dict])->list[dict]:
    """Return overlay and gaps without treating padding as executable content."""
    output=[]
    if primary and 0<primary.get("logical_end",physical_size)<physical_size:
        start=primary["logical_end"];output.append({"type":"overlay_data","start_offset":start,"end_offset":physical_size,"length":physical_size-start,"confidence":.99,"evidence":["byte oltre la fine logica del formato primario"]})
    spans=sorted((r.get("offset",0),r.get("offset",0)+r.get("size",0)) for r in regions if r.get("size") and r.get("valid_bounds"))
    cursor=0
    for start,end in spans:
        if start>cursor and start-cursor>=256:output.append({"type":"unreferenced_data","start_offset":cursor,"end_offset":start,"length":start-cursor,"confidence":.65,"evidence":["intervallo non coperto da sezioni validate"]})
        cursor=max(cursor,end)
    return output
