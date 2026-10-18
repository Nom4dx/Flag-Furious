# Steganography Forensics (`seganografy`)

Plugin passivo e general-purpose per Forensic Hub. Identifica il formato reale, valida firme e confini, cerca canali steganografici in testo/Unicode/immagini/audio/video/documenti/container, conserva ogni payload estratto, applica decoder ricorsivi limitati, cerca flag con provenienza e produce grafi e visualizzazioni JSON.

## Architettura e uso

`plugin.py` orchestra moduli indipendenti e fault-isolated in `src/`. Il loader usa `entrypoint.py`; l'alias `steganography-forensics` risolve allo stesso ID. Selezionare il plugin nella pagina di acquisizione. Opzioni supportate in `plugin_options.seganografy`: `password` (mai brute-force) e `video_modes`. Ogni parser restituisce dati strutturati; nessun contenuto viene eseguito.

## Formati e tecniche

Testo UTF-8/UTF-16, Unicode invisibile/bidi/homoglyph, HTML/Markdown/JSON/XML, whitespace, PNG/JPEG/BMP/GIF/TIFF/WebP/AVIF/HEIC/SVG/PSD, WAV/AIFF/AU/FLAC/MP3/OGG/Opus/M4A, MP4/MKV/AVI/MOV/WebM/MPEG, PDF/Office/RTF/ODF/EPUB, ZIP e binari. Le estrazioni LSB/MSB registrano bit, canali, ordine, inversione, step e offset. DCT/DWT, phase/echo/spread-spectrum/QIM e anomalie statistiche sono indicatori euristici: non vengono dichiarati estrazioni confermate senza bytes validabili.

## Dipendenze

Obbligatorie: Python 3.11+ e il contratto dell'Hub. Pillow e NumPy migliorano immagini/audio ma hanno fallback. Binari opzionali: `binwalk`, `steghide`, `stegseek` (spelling corretto), `zsteg`, `stegcloak`, `stegsnow`, `openstego`, `exiftool`, `ffprobe`, `ffmpeg`, `sox`, ImageMagick, `pngcheck`, `jpeginfo`, `strings`, `file`, `xxd`, `foremost`, `tesseract`, `zbarimg`. La loro assenza non interrompe il plugin.

## Output e artefatti

Le sezioni sono File Identity, Detection Summary, Text, Unicode, Whitespace, Image, Audio, Video, Document, Binary/Container, External Tools, Decoder Chains, Extracted/Uninterpreted Artifacts, Flags, Findings, Graph, Warnings, Errors e Metrics. Un file estratto non identificabile resta `extracted_uninterpreted`, con SHA-256 e finding dedicato. La directory derivata del caso contiene `carved/`, `container/`, `media/`, `unicode/`, `decoded/` e `report/report.json`.

## Sicurezza e limiti

L'originale è aperto in sola lettura. Niente rete, shell, macro, script, JavaScript PDF, HTML attivo o eseguibili. ZIP Slip, symlink, duplicati e archive bomb sono bloccati. `Limits` impone depth, output, singolo artefatto, numero file/frame/tentativi, rapporto di espansione e timeout. I validator completi esistono per PNG/JPEG/ZIP/PDF/RIFF; i formati senza un confine deterministico ricevono confidence ridotta. Il tipo degli artefatti derivati è determinato leggendo al massimo 1 MiB; file più grandi sono etichettati con detection parziale e il job lo segnala.

Le fasi in memoria leggono al massimo 64 MiB. Se il budget concesso o la vista
montata è più ampia, il risultato segnala `partial` e separa vista letta,
dimensione fisica e byte budget nelle metriche.
Le euristiche testuali, Unicode e whitespace leggono al massimo 8 MiB e segnano
moduli ed eventi di fase `partial` se il testo è più lungo. L'inventario Unicode
limita le righe sospette e mixed-script a 10.000, i simboli
decodificati a 100.000 e le viste derivate a 100.000 codepoint; le omissioni
sono conteggiate e rendono parziale la sezione e l'analisi.

## Estensione

Per aggiungere un decoder, implementare una funzione pura e limitata in `src/decoders.py`, registrarla in `decode_candidates` e aggiungere una fixture con falso positivo. Per una tecnica, creare un modulo `analyze(...)` che restituisca candidate/finding/artifact con tecnica, prova e confidence, quindi collegarlo a una fase in `plugin.py`. Non elevare mai un indicatore statistico a certezza.

## Test

`python -m pytest plugins/seganografy/tests tests` verifica firme/limiti, Unicode, decoder, LSB, WAV, documenti, ZIP sicuro, output JSON, alias, immutabilità e comportamento scroll. Le fixture sono generate localmente dai test, senza rete.
