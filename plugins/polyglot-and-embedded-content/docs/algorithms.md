# Algoritmi e offset

Gli intervalli usano `[start_offset, end_offset)`: `length = end - start`. PNG
somma header, lunghezza, tipo, payload e CRC fino a IEND. JPEG percorre i marker,
rispetta le lunghezze big-endian e ignora soltanto byte stuffed/restart durante
lo scan. ZIP verifica che central directory ed EOCD siano relativi all'inizio
dell'archivio, poi `zipfile.testzip()` prova i CRC. PDF controlla che
`startxref < %%EOF` e punti a xref oppure a un oggetto xref stream plausibile.

Le coppie di intervalli vengono classificate come disgiunte, contenute o
sovrapposte. Un formato a offset zero seguito da uno disgiunto è suffix; uno
contenuto nel range di un altro è embedded; intersezioni parziali sono overlap.
Eseguibile/script seguito da archivio validato aggiunge la classe SFX.

Il carving copia esattamente l'intervallo validato. L'estrazione ZIP usa solo la
central directory validata. La ricorsione è affidata al job manager dell'hub,
che registra parent asset, hash, profondità e coppie già eseguite.

Le flag ricevono più peso quando provengono da contenitore validato, entry con
CRC corretto o catena decoder coerente. Una semplice strings su formato respinto
resta `suspicious`; non viene promossa soltanto per il prefisso.

