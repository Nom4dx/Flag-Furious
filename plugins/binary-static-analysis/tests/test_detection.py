"""Signature, boundary, carving and encrypted-container tests."""
import importlib


def test_signature_found_is_not_validation(package,fixtures):
    magic=importlib.import_module(package+".src.magic_detection")
    candidates,_=magic.scan(fixtures/"false-signatures.bin",10_000)
    valid,rejected=magic.validate(fixtures/"false-signatures.bin",candidates,10_000)
    assert candidates and not valid and rejected


def test_embedded_png_zip_boundaries(package,fixtures,tmp_path):
    magic=importlib.import_module(package+".src.magic_detection")
    artifacts=importlib.import_module(package+".src.artifact_manager")
    carving=importlib.import_module(package+".src.carving")
    path=fixtures/"raw-embedded.bin";candidates,_=magic.scan(path,path.stat().st_size)
    valid,_=magic.validate(path,candidates,path.stat().st_size)
    assert {x["format"] for x in valid}>={"png","zip"}
    rows,warnings=carving.carve(path,valid,artifacts.ArtifactManager(tmp_path,10_000_000),path.stat().st_size)
    assert rows and not warnings and all(x["validated"] for x in rows)


def test_compression_and_cpio(package,fixtures):
    magic=importlib.import_module(package+".src.magic_detection")
    for name in ("payload.gz","payload.xz","payload.bz2","cpio.bin"):
        path=fixtures/name;candidates,_=magic.scan(path,path.stat().st_size);valid,_=magic.validate(path,candidates,path.stat().st_size)
        assert valid,name


def test_zipcrypto_requests_bruteforce(package,fixtures):
    magic=importlib.import_module(package+".src.magic_detection")
    crypto=importlib.import_module(package+".src.crypto_detector")
    path=fixtures/"encrypted.zip";candidates,_=magic.scan(path,path.stat().st_size);valid,_=magic.validate(path,candidates,path.stat().st_size)
    indicators,requests=crypto.detect(path,valid,{"global":5.0},"asset-1")
    bridge=importlib.import_module(package+".src.bruteforce_bridge")
    requests=bridge.requests_from(indicators,requests)
    assert any(x["type"]=="password_required" for x in indicators)
    assert requests and requests[0]["source_plugin"]=="binary-static-analysis"
