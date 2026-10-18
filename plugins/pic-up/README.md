# pic-up

Adapter per triage offline di PCAP/PCAPNG, immagini, archivi e carving. Non viene
avviato su file arbitrari né su immagini disco già assegnate agli analizzatori
filesystem. Le modalità automatiche non indovinano password, chiavi o filtri.
L'adapter richiede firme PCAP/PCAPNG, immagine o archivio; estensione e MIME
dedotti dal solo nome non sono sufficienti. Per i contenitori RIFF accetta come
immagine solo WebP, evitando di avviare l'estrazione immagini su WAV e AVI.

I prefissi configurati sono passati tutti al decoder. Le flag restano candidate e
mantengono encoding/fonte; le diagnostiche del decoder sono riportate come warning
e limiti/cap di scansione rendono il risultato parziale. Gli hash del report
distinguono l'evidenza originale dalla vista eventualmente limitata al byte budget.

## Dipendenze e limiti

TShark, Capinfos, Tesseract ed ExifTool sono opzionali: le sezioni che ne dipendono
possono non essere disponibili. L'analisi di input oltre il budget è parziale; un
report senza candidate non dimostra che il file completo sia privo di payload.
La scansione raw ha inoltre un cap interno di 128 MiB: il superamento è
segnalato come parziale anche quando il budget concesso dal job è maggiore; i
log allegati dichiarano separatamente il troncamento del prefisso analizzato.
Ogni diagnostica del parser rende il risultato `partial`, poiché il parser storico
non distingue ancora omissioni di copertura da messaggi informativi. Gli artefatti
carvati ed esportati riportano la fonte registrata dal parser insieme all'asset
genitore; il rendering mostra entrambi quando sono disponibili.
La sezione di analisi espone lo stesso stato `partial`/`completed` del risultato
principale, affinché la dashboard evidenzi anche a livello di sezione una coverage
incompleta.
