# Host Artifact Forensics

Plugin offline per inventariare database SQLite nei file o nei profili acquisiti
e ricostruire cronologia/download da Chromium, Firefox e Safari. Non interroga
profili live, dispositivi o servizi remoti. Questa prima versione non è un parser
generico di ogni schema applicativo e non analizza Registry, EVTX, plist o cache
browser LevelDB.

## Fonti e output

Riconosce il database dal magic SQLite, non dalla sola estensione. Per ogni DB
registra il percorso relativo alla directory importata, SHA-256 dei byte copiati,
dimensione e presenza di WAL. Copia DB e `-wal` nella directory isolata prima di
aprire SQLite in sola lettura. Riconosce le tabelle di visite di Chromium,
Firefox Places e Safari History; inventaria nomi e colonne anche per schemi non
riconosciuti. Un profilo si importa come directory per associare correttamente
database e sidecar.
L'ID degli eventi è derivato dall'hash dello snapshot DB+WAL, mentre i campi
`source_sha256` e `source_snapshot_sha256` distinguono il file principale dalla
vista transazionale analizzata.

Le visite e i download includono timestamp UTC normalizzato, valore raw, browser,
URL/titolo o destinazione, dominio, tabella, row ID, sorgente e hash del database.
I cookie e i database di credenziali sono solo segnalati per presenza: il plugin
non legge i valori dei cookie, password o token e non li decritta. Le flag sono
candidati trovati soltanto nei campi URL/titolo estratti entro i limiti.

## Limiti e sicurezza

Il byte budget è cumulativo per database e WAL. Sono esaminati al massimo 128
database, 10.000 eventi, 10.000 file e 10.000 directory durante l'inventario;
il matcher di compatibilità controlla al massimo 512 file e 512 directory. Le
flag candidate sono limitate a 100. I valori testuali sono limitati e
SQLite usa `mode=ro`, `query_only`, `trusted_schema=OFF` e progress handler con
timeout. DB e WAL parziali, schema non riconosciuti, timeout e limiti sono
riportati come copertura `partial`. Le copie di lavoro vengono eliminate prima
del ritorno del risultato; gli originali non sono modificati.

## Interpretazione

Una visita prova che una riga era presente nel database acquisito, non chi l'ha
prodotta né che il sito sia stato raggiunto con successo. I timestamp mantengono
anche il valore raw e il sistema di origine. WAL/SHM non inclusi nella directory
acquisita possono lasciare transazioni non visibili. File cancellati, freelist,
carving SQLite, login/cookie e cache non sono coperti in questa versione.
