# Fixture locali

Le fixture sono generate deterministicamente da `tests/conftest.py`: PNG con
CRC reali, JPEG a segmenti, PDF con `startxref` coerente e ZIP prodotti da
`zipfile`. La generazione evita blob opachi nel repository e permette di creare
varianti per trailing data, prefissi, chunk custom, entry traversal, CRC errati,
archivi annidati e flag presenti soltanto nei livelli interni.

