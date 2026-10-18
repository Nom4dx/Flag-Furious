"""Tests for strings, entropy and both declarative graph views."""
import importlib


def test_strings_offsets_and_categories(package,fixtures):
    strings=importlib.import_module(package+".src.strings_analyzer")
    rows=strings.extract((fixtures/"strings.bin").read_bytes())
    assert any(x["category"]=="url" and x["offset"]==0 for x in rows)
    assert any(x["encoding"]=="utf-16le" for x in rows)


def test_entropy_is_indicator(package,fixtures):
    entropy=importlib.import_module(package+".src.entropy_analyzer")
    result=entropy.scan(fixtures/"entropy.bin",100_000)
    assert 7.9<=result["global"]<=8.0
    assert result["category"] in {"compressed_likely","random_or_unknown","encrypted_likely"}


def test_structure_and_code_graph(package):
    graph=importlib.import_module(package+".src.graph_builder")
    parsed={"format":"elf","header":{"header_size":64},"sections":[{"index":1,"name":".text","offset":64,"size":1,"permissions":"RX","valid_bounds":True}],"segments":[]}
    structure=graph.structure("sample.bin",128,parsed,[],[],[])
    assert structure["nodes"] and any(x["relation"]=="contains" for x in structure["edges"])
    code=graph.code([{"virtual_address":4096,"status":"validated"}],{"functions":[{"id":"function-1000","address":4096,"classification":"function_confirmed"}],"blocks":[],"calls":[]},[],[])
    assert any(x["type"]=="entrypoint" for x in code["nodes"])
