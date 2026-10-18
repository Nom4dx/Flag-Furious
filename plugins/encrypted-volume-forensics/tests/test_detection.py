"""Detection tests verify content-first FVE matching and partition offsets."""
from conftest import load_module

def test_bounded_probe_ignores_extension(whole_fve):
    detector=load_module('src.bitlocker_detector');result=detector.probe(whole_fve)
    assert result['compatible'] and result['score']>=.99 and result['candidate_offsets']==[0]

def test_mbr_partition_and_volume_offset(mbr_fve):
    partitions=load_module('src.partition_detector').inspect(mbr_fve)
    assert partitions['scheme']=='MBR' and partitions['partitions'][0]['offset']==1048576
    volumes,truncated=load_module('src.volume_detector').detect(mbr_fve,partitions['partitions'],mbr_fve.stat().st_size)
    assert not truncated and volumes[0]['offset']==1048576 and volumes[0]['validated']

def test_metadata_offsets_are_bounded(whole_fve):
    volume=load_module('src.volume_detector').detect(whole_fve,[],whole_fve.stat().st_size)[0][0]
    rows=load_module('src.fve_parser').metadata_copies(whole_fve,volume)
    assert [row['relative_offset'] for row in rows]==[65536,131072,196608]
    assert all(row['length']==4096 for row in rows)
