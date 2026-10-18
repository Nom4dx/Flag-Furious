# Contratto dei parser

Un parser riceve un `Path` e un byte budget, usa `BinaryReader` per bounds check e
restituisce dizionari JSON con `validated`, `header`, regioni, `logical_end` e
finding. Solleva `ValueError` per incoerenze recuperabili. Nuovi parser devono
limitare contatori e string table, evitare mmap writable, non importare/eseguire
il campione e documentare l'origine di ogni offset.
