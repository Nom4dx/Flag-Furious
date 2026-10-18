# Registro firme

Ogni record contiene formato, bytes, offset relativo, validator, marker finali e
confidenza preliminare. TAR e ISO9660 usano rispettivamente gli offset relativi
257 e 32769. La scansione conserva un overlap pari alla firma più lunga più il
massimo offset relativo, quindi trova marker divisi tra due blocchi.

`PK\x01\x02` e `PK\x05\x06` sono marker secondari: compaiono nell'inventario ma
non sono radici di carving. PDF, ZIP, PNG, JPEG, GIF, RIFF, compressori,
eseguibili, database, bytecode, archivi, OLE, XML, HTML e script sono definiti in
`src/signatures.py`. Una firma respinta conserva contesto esadecimale, offset e
motivo del validator.

