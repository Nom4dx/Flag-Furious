# pic-up

Adapter per triage offline di PCAP/PCAPNG, immagini, archivi e carving. Non viene
avviato su file arbitrari né su immagini disco già assegnate agli analizzatori
filesystem. Le modalità automatiche non indovinano password, chiavi o filtri.

I prefissi configurati sono passati tutti al decoder. Le flag restano candidate e
mantengono encoding/fonte; le diagnostiche del decoder sono riportate come warning
e limiti/cap di scansione rendono il risultato parziale. Gli hash del report
distinguono l'evidenza originale dalla vista eventualmente limitata al byte budget.

## Dipendenze e limiti

TShark, Capinfos, Tesseract ed ExifTool sono opzionali: le sezioni che ne dipendono
possono non essere disponibili. L'analisi di input oltre il budget è parziale; un
report senza candidate non dimostra che il file completo sia privo di payload.
