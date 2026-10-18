import gzip
import io
import zipfile
import pytest
from diskhunt.artifacts import ArtifactCatalog, detect_mime
from diskhunt.db import Database
from diskhunt.extraction import ExtractionLimits, RecursiveExtractor
from diskhunt.scanner import compile_flag_patterns


def catalog(tmp_path):
    db=Database(tmp_path/"db.sqlite"); db.create_job("j","x.img",str(tmp_path/"x.img"),{})
    root=tmp_path/"artifacts"; root.mkdir(); return db,ArtifactCatalog(db,"j",root,compile_flag_patterns("CTF{",False)),root


def test_recursive_gzip_flag_and_provenance(tmp_path):
    db,cat,root=catalog(tmp_path); archive=root/"flag.gz"
    with gzip.open(archive,"wb") as out: out.write(b"inside CTF{compressed_flag}")
    parent=cat.register(archive,original_path="logs/flag.gz",inode=42,partition=1,filesystem="FAT32")
    children=RecursiveExtractor(cat,root/"extracted").expand(parent)
    assert children and children[0]["parent_artifact"]=="flag.gz"
    assert db.results("j","flag")[0]["candidate"]=="CTF{compressed_flag}"


def test_zip_navigation_and_mime(tmp_path):
    db,cat,root=catalog(tmp_path); archive=root/"evidence.zip"
    with zipfile.ZipFile(archive,"w") as z: z.writestr("folder/note.txt","CTF{zip_nested}")
    parent=cat.register(archive,original_path="evidence.zip"); children=RecursiveExtractor(cat,root/"extracted").expand(parent)
    assert children[0]["original_path"]=="evidence.zip"; assert children[0]["mime_type"]=="text/plain"


def test_archive_path_traversal_rejected(tmp_path):
    _,cat,root=catalog(tmp_path); archive=root/"evil.zip"
    with zipfile.ZipFile(archive,"w") as z: z.writestr("../../escape.txt","bad")
    parent=cat.register(archive); extractor=RecursiveExtractor(cat,root/"extracted")
    assert extractor.expand(parent)==[]; assert extractor.warnings; assert not (tmp_path/"escape.txt").exists()


def test_decompression_bomb_ratio_rejected(tmp_path):
    _,cat,root=catalog(tmp_path); archive=root/"bomb.zip"
    with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as z: z.writestr("zeros.bin",bytes(200000))
    parent=cat.register(archive); extractor=RecursiveExtractor(cat,root/"extracted",ExtractionLimits(max_ratio=10))
    assert extractor.expand(parent)==[]; assert extractor.warnings

