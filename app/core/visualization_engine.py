import math

# Plugins select a semantic palette by name.  Keeping the actual colors here
# prevents arbitrary or unreadable colors from entering the UI through JSON.
PALETTES = {
    "forensic": {"background": "#080a0d", "surface": "#11151a", "foreground": "#f4f7f5", "primary": "#27d6a1", "secondary": "#f1c75b", "critical": "#ff6b6b", "muted": "#87929c"},
    "document": {"background": "#0b0907", "surface": "#17120d", "foreground": "#fff8e7", "primary": "#d9a441", "secondary": "#71c4d6", "critical": "#e36b6b", "muted": "#9d9485"},
    "filesystem": {"background": "#070b09", "surface": "#0e1813", "foreground": "#effff7", "primary": "#48c98b", "secondary": "#d9c95e", "critical": "#ef6a6a", "muted": "#789488"},
    "network": {"background": "#070a0d", "surface": "#0d151c", "foreground": "#edf9ff", "primary": "#42bce8", "secondary": "#a78bfa", "critical": "#ff6f7d", "muted": "#768e9b"},
    "signal": {"background": "#0b080d", "surface": "#18101d", "foreground": "#fff3ff", "primary": "#db73ef", "secondary": "#61d8d0", "critical": "#ff7171", "muted": "#96829b"},
    "archive": {"background": "#0d0906", "surface": "#1a120b", "foreground": "#fff7ed", "primary": "#f0a34a", "secondary": "#e3d15b", "critical": "#ef6f61", "muted": "#9d8b78"},
    "code": {"background": "#08090d", "surface": "#11131c", "foreground": "#f2f2ff", "primary": "#8fa8ff", "secondary": "#55d6be", "critical": "#ff6f91", "muted": "#85899d"},
    "volume": {"background": "#07090c", "surface": "#101722", "foreground": "#f2f7ff", "primary": "#56a8ff", "secondary": "#d6b85c", "critical": "#f06b78", "muted": "#7f8c9d"},
    "text": {"background": "#090909", "surface": "#151515", "foreground": "#fafafa", "primary": "#e5cf68", "secondary": "#66c7b5", "critical": "#eb7070", "muted": "#909090"},
    "monochrome": {"background": "#000000", "surface": "#111111", "foreground": "#ffffff", "primary": "#ffffff", "secondary": "#bdbdbd", "critical": "#ffffff", "muted": "#808080"},
}

TYPES = {
    "line",
    "bar",
    "area",
    "scatter",
    "histogram",
    "heatmap",
    "pie",
    "donut",
    "timeline",
    "tree",
    "graph",
    "execution_graph",
    "matrix",
    "coordinates",
    "distribution",
    "comparison",
    "diff",
    "hex_map",
    "byte_grid",
    "offset_map",
    "network_graph",
}


def validate_visualization(value):
    value = dict(value)
    inferred = "type" not in value
    raw_data = value.get("data")
    kind = value.setdefault("type", "graph" if isinstance(raw_data, dict) and "nodes" in raw_data else "bar")
    if kind not in TYPES:
        raise ValueError(f"Tipo visualizzazione non supportato: {kind}")
    data = value.get("data")
    if kind in {"graph", "network_graph", "execution_graph", "tree"}:
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("nodes"), list)
            or not isinstance(data.get("edges", []), list)
        ):
            raise ValueError("Il grafo richiede nodes e edges")
        if len(data["nodes"]) > 2000 or len(data.get("edges", [])) > 10000:
            raise ValueError("Grafo oltre il limite di nodi o collegamenti")
        ids = [n.get("id") for n in data["nodes"] if isinstance(n, dict)]
        if (
            len(ids) != len(data["nodes"])
            or any(not isinstance(id, str) for id in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("Il grafo richiede ID stringa univoci")
        if any(
            not isinstance(e, dict) or e.get("source") not in ids or e.get("target") not in ids
            for e in data.get("edges", [])
        ):
            raise ValueError("Collegamento a un nodo inesistente")
    elif not isinstance(data, list):
        raise ValueError("La visualizzazione richiede una lista data")
    if len(data) > 10000:
        raise ValueError("Massimo 10000 elementi per visualizzazione")
    if kind in ("line", "bar", "area", "scatter", "coordinates", "comparison", "offset_map", "pie", "donut"):
        yfield = value.get("encoding", {}).get("y", {}).get("field", "y")
        if any(
            not isinstance(row, dict) or not isinstance(row.get(yfield, row.get("value")), (int, float))
            for row in data
        ):
            raise ValueError("Il grafico richiede valori numerici sull’asse y/value")
    if kind in ("heatmap", "matrix") and data and isinstance(data[0], list):
        width = len(data[0])
        if any(not isinstance(row, list) or len(row) != width for row in data) or width * len(data) > 10000:
            raise ValueError("Matrice irregolare o troppo grande")

    def finite(x):
        if isinstance(x, float) and not math.isfinite(x):
            raise ValueError("Coordinate non finite")
        if isinstance(x, dict):
            for v in x.values():
                finite(v)
        if isinstance(x, list):
            for v in x:
                finite(v)

    finite(data)
    palette = value.get("palette", "forensic")
    if palette not in PALETTES:
        raise ValueError(f"Palette non supportata: {palette}")
    value["palette"] = palette
    value["style"] = PALETTES[palette]
    value["inferred"] = inferred
    return value
