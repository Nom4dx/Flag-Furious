from diskhunt.scanner import compile_flag_patterns, scan_bytes


def test_ascii_art_flag_is_marked_as_heuristic():
    data=b"( C ) ( T ) ( F ) ( { ) ( a ) ( r ) ( t ) ( } )"
    result=scan_bytes(data,100,compile_flag_patterns("CTF{",False))[0]
    assert result["candidate"]=="CTF{art}"; assert "RICOSTRUZIONE PARZIALE" in result["status"]; assert result["confidence"]<=72
