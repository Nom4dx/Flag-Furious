# Sicurezza

L'input è un bind read-only nel worker bubblewrap senza rete. I tool ammessi sono
parser passivi con argomenti fissi, `shell=False`, timeout e stdout/stderr bounded.
Carving usa nomi sanitizzati, SHA-256, directory interne e budget; ZIP extraction
rifiuta path traversal, symlink, rapporti di espansione eccessivi e file troppo
grandi. Nessun artefatto viene eseguito. Le regole YARA sono solo locali.
