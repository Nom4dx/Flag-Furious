# Sicurezza
Input passivo e immutabile; output solo nel caso. `safe_subprocess.py` usa allowlist, array argv, `shell=False`, ambiente minimo, timeout e output cap. Gli archivi rifiutano path assoluti, `..`, drive, NUL e symlink e applicano limiti di espansione. Hash dedupe impedisce cicli. Nessun payload, macro, script o formula viene eseguito; nessuna rete è richiesta.
