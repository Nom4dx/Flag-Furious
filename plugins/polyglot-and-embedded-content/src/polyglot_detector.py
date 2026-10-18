"""Classify validated interval relationships into polyglot categories."""

from .concatenation import find_concatenations


def classify_polyglot(file_size: int, formats: list[dict]) -> dict:
    """Classify prefix, suffix, embedded, overlapping, concatenated and SFX forms.

    Only validated ranges participate. Output includes every reason and a primary
    class. Empty/single ordinary formats are not called polyglots.
    """
    relations, classes = [], set()
    ordered = sorted(formats, key=lambda x: (x["start_offset"], -x["end_offset"]))
    for i, left in enumerate(ordered):
        for right in ordered[i + 1:]:
            if right["start_offset"] >= left["end_offset"]:
                relations.append({"source": left["id"], "target": right["id"], "relation": "concatenated_after"})
                classes.add("suffix_polyglot" if left["start_offset"] == 0 else "concatenated_files")
            elif right["end_offset"] <= left["end_offset"]:
                relations.append({"source": left["id"], "target": right["id"], "relation": "contains"})
                classes.add("embedded_polyglot")
            elif right["start_offset"] < left["end_offset"]:
                relations.append({"source": left["id"], "target": right["id"], "relation": "overlaps"})
                classes.add("overlapping_polyglot")
    if ordered and ordered[0]["start_offset"] > 0:
        classes.add("prefix_polyglot")
    executable = {"pe", "elf", "macho", "script", "shell_script", "python_script", "javascript", "powershell", "batch"}
    if any(x["format"] in executable for x in ordered) and any(x["format"] in {"zip", "7z", "rar", "tar"} and x["start_offset"] > 0 for x in ordered):
        classes.add("sfx")
    priority = ["sfx", "overlapping_polyglot", "embedded_polyglot", "suffix_polyglot", "prefix_polyglot", "concatenated_files"]
    return {
        "is_polyglot": len(ordered) > 1 or bool(classes),
        "primary_classification": next((x for x in priority if x in classes), "single_format" if ordered else "unvalidated"),
        "classifications": sorted(classes),
        "relations": relations,
        "concatenations": find_concatenations(ordered),
        "validated_format_count": len(ordered),
        "physical_size": file_size,
    }
