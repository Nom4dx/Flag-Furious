# Formati supportati

I formati con confine preciso sono PNG (IEND e CRC), JPEG (segmenti ed EOI), ZIP
(EOCD, central directory e CRC), PDF (startxref e EOF), RIFF (dimensione), GZIP,
BZip2, XZ, TAR, CPIO, 7z, PE, ISO9660 e HTML. ELF, Mach-O, SQLite, Java, WASM,
OLE, XML, GIF e script dispongono di controlli strutturali con i limiti descritti
in `limitations.md`. RAR espone `boundary_exact: false`.

Le estensioni sono soltanto segnali di routing. Il formato mostrato nella
dashboard proviene sempre da un validator riuscito.

