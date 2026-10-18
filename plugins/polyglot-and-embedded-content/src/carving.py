"""Configuration and policy layer for validated offset carving."""

from .embedded_extractor import carve_validated


def carve(path, boundaries, store, config):
    """Apply format/range filters before verified carving.

    Input mirrors the documented ``start_offset/end_offset/formats`` request.
    Output is artifacts and warnings. Unvalidated objects are never accepted;
    recursion is delegated to the hub's derived-asset pipeline with SHA dedupe.
    """
    selected = [item for item in boundaries if item.get("validated") and item["format"] in config.get("formats", []) and item["start_offset"] >= config.get("start_offset", 0) and (config.get("end_offset") is None or item["end_offset"] <= config["end_offset"])]
    return carve_validated(path, selected, store, config.get("max_object_bytes", 64 * 1024 * 1024))

