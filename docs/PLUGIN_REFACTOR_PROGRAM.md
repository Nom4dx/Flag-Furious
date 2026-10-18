# Programma di rifacimento dei plugin

Questo programma impone la sequenza richiesta: finire e consolidare tutti i plugin
presenti prima di iniziare plugin di dominio nuovi. Un adapter che inoltra risultati
legacy conta come plugin presente e deve superare gli stessi criteri.

## Regole di consegna

Ogni plugin passa attraverso tre stati Git separati: `audit`, `refactor`, `done`.
Un plugin è `done` solo quando:

1. matcher selettivi basati su evidenza (la sola estensione non prova il formato);
2. limiti di input, tempo, output e ricorsione espliciti e rispettati;
3. errore/parzialità e dipendenze assenti visibili nel risultato;
4. finding, asset e tempi legati a una fonte/offset o record verificabile;
5. output ordinato con schema e vista leggibile, senza campi JSON opachi evitabili;
6. fixture positive, negative, malformate e troncate per i parser in scope;
7. README, manifest, capabilities e matrice formato × funzione coerenti.

Il lavoro su ogni gruppo termina con revisione del diff e commit. I test vanno eseguiti
prima di promuovere una fase; ogni plugin che non può essere testato nell'ambiente
disponibile resta esplicitamente `refactor`, con motivazione. Le regressioni non si
nascodono aggiornando attese senza spiegazione.

## Gruppo A — Adapter e analisi generalista

| Ordine | Plugin | Obiettivo del rifacimento |
| ---: | --- | --- |
| 1 | `archive-extractor` | Budget cumulativi e rapporto di espansione, percorsi Unicode/Windows, collisioni e duplicati, ZIP64/encryption, CRC, inventario membri esclusi e provenienza/offset per ogni file |
| 2 | `text-inspector` | Decodifica esplicita e troncamento, Unicode/invisibili, line/byte offset, hash e tipo dati, evitare JSON duplicato in output e rendere la distribuzione filtrabile |
| 3 | `pic-up` | Eliminare compatibilità generica che lo avvia su PDF/binari non pertinenti; separare PCAP, immagini e carving; invocare solo le modalità giustificate dal formato |
| 4 | `hidgrabber` | Matcher PCAP, output per dispositivo/tasto con timestamp e frame, input PCAPNG e limiti di report chiari |
| 5 | `githappens` | Matcher Git/directory/archive/disk specifici; distinguere errore modulo da assenza di reperti; proteggere archivio/file-system traversals; timeline e cache con origine |
| 6 | `ext4atto` | Audit immagine/partizioni, limiti TSK e filesystem supportati; rendere recoverability e tool mancanti chiari; collegare offset filesystem ai derivati |

## Gruppo B — Parser specialistici

| Ordine | Plugin | Obiettivo del rifacimento |
| ---: | --- | --- |
| 7 | `binary-static-analysis` | Matrice formato/funzione, versioni CLI, parser bounded per PE/ELF/Mach-O/firmware, separare firma/validazione e dettagliare analisi non eseguite |
| 8 | `document-metadata-forensics` | Copertura per MIME/formato, normalizzazione timezone, metadata sensibili con sorgente, PDF/OLE/OOXML e struttura invalidi/parziali |
| 9 | `polyglot-and-embedded-content` | Risolvere confini ambigui, evitare duplicati con archivio/stego, mostrare tutte le interpretazioni e validazioni indipendenti |
| 10 | `seganografy` | Separare indicatori statistici dai payload decodificati, supportare provenienza esatta e stato inconclusivo per tool mancanti |
| 11 | `log-forensics` | Schema/versione fonte, timestamp e timezone, parsing multi-file, ranking correlazioni, regole identificate/versionate e coverage per parser |
| 12 | `encrypted-volume-forensics` | Pipeline BitLocker per versione/caso, offset chiavi e protettori, distinzione rilevato/sbloccato/validato, nessuna scrittura volume |
| 13 | `bruteforce` | Scopo limitato a recovery autorizzato, verifica adapter per formato, tentativi/tempo/accounting, segreti effimeri e prova di password senza estrazione non richiesta |

## Ordine e gate

1. **A0 — Contratto e baseline:** stabilire un glossario di finding, status, coverage,
   provenance e formati. Registrare matcher, parser, CLI, fixture, output/costi di tutti
   i plugin senza cambiare l'API pubblica.
2. **A1 — Gruppo A:** rifare e chiudere in ordine i sei adapter/generalisti della tabella.
   Ripetere i percorsi di integrazione che attraversano derivati e workflow.
3. **A2 — Gruppo B:** rifare i sette specialisti. Per i plugin che condividono formati,
   definire il proprietario del parser e i confini di responsabilità prima delle modifiche.
4. **A3 — Chiusura plugin presenti:** nessun plugin può restare in `audit`; tutti i
   plugin legacy devono aver completato il rifacimento, la revisione e i gate di fixture,
   contratto e runtime prima di promuoverli a `done`. Rilievi aperti restano registrati
   come debito `refactor`. Non si avviano moduli nuovi prima della chiusura A3.
5. **B1 — Host artifact forensics:** SQLite/WAL, browser, Windows Registry/EVTX,
   macOS plist/Unified Logs, Linux journald; implementazione incrementale con schema
   comune e correlazione timeline.
6. **B2 — Email e messaggistica:** EML/MBOX prima, poi PST/OST tramite parser esterno
   isolato; MIME/allegati/thread e timezone.
7. **B3 — Memory forensics:** adapter Volatility 3 per dump, symbols verificabili,
   processi/moduli/reti e risultati parziali con plugin mancanti.
8. **B4 — Mobile e cloud offline:** import di backup/export come evidenza; niente
   connessione al dispositivo o tenant in automatico.
9. **B5 — Acquisizione live/remota:** non pianificata finché non sono approvati
   threat model, autenticazione, autorizzazione e audit dedicati.

## Registro di avanzamento

| Plugin | Stato | Commit/nota |
| --- | --- | --- |
| archive-extractor | refactor | Matcher ZIP corretto; AES/ZipCrypto distinti; inventario 10.000; membri max 16 MiB e ratio 1.000:1; CRC, SHA-256 e offset nei derivati. Restano validatori e fixture |
| text-inspector | refactor | Preview UTF-8 16 KiB, serializzazione inline progressiva, conteggi/hash su max 64 MiB e copertura parziale; restano offset e decodifica dichiarata |
| pic-up | refactor | Matcher limitato a stream, immagini e archivi; scanner TShark/capinfos/file/OCR bounded per output e timeout, massimo 100.000 righe per query; export inventariati/hashati entro 10.000 file/64 MiB e scan contenuti export entro budget; artefatti da comandi interrotti marcati incompleti/esclusi, warning rendono `partial`. Restano fixture, limiti globali delle liste/stream e accounting subprocess |
| hidgrabber | refactor | Wrapper inoltra tutti i prefissi e propaga candidate; TShark limitato per tempo/byte/righe; hash core riusato e `capinfos` con timeout; diagnostics producono `partial` |
| githappens | refactor | Matcher per directory, archivi, immagini disco e bundle; copia input limitata, output derivati max 64/budget; estrazione ricorsiva streaming con budget cumulativo da 256 MiB; materializzazione virtuale limitata a 512 MiB e 300 s; scanner, decompressione, History, Slack, cache SQLite, Git oggetti, reference diff e capture subprocess con cap di byte/record/percorso e warning parziali. Restano copertura fixture e verifica dei percorsi pipeline |
| ext4atto | refactor | Matcher immagine/partizioni; query risultati limitate, anteprima legge 2 MiB e riusa hash indicizzati; stdout/stderr TSK bounded, recupero inode e blocchi capped, 7z/PDF estratti per-member su output limitato, espansione ricorsiva con timeout globale, avvisi propagati a `PARTIAL`. TSK resta non contabilizzato nel byte budget del core; fixture/runtime ancora aperti |
| binary-static-analysis | refactor | Warning di coverage; entropy/string limits e input parziale espliciti; YARA limitato a prefisso 64 MiB e disassembly max 20.000 istruzioni |
| document-metadata-forensics | refactor | Matcher allineato; source size separata dalla vista; regex custom con timeout, cap testo e contesto configurato |
| polyglot-and-embedded-content | refactor | Flag scan artefatti bounded e parzialità dichiarata anche per vista importata incompleta; decoder gzip/zlib con max output reale, totale 32 MiB e 2.000 tentativi; cap dichiarati in metriche e warning; restano confini/duplicati e fixture |
| seganografy | refactor | Type detection artefatti limitata a 1 MiB; zTXt e decoder gzip/zlib capped con stato parziale; subprocess stdout/stderr streaming bounded; video frames/audio con byte/artifact cap e output budget condiviso; timeout/troncamento propagati a warning/partial. Restano falso positivi, coverage per formato e fixture |
| log-forensics | refactor | Directory/file e contenitori compressi letti entro budget con espansione limitata; output eventi/decoder clamp; identity riusa hash core; inline partial visibile; revisione statica aggiornata |
| encrypted-volume-forensics | refactor | Ogni warning e vista importata parziale producono `partial`; hash disabilitato esplicitamente risulta `skipped`; restano matrice BitLocker |
| bruteforce | refactor | Matcher bounded; inventory wordlist budgetato e righe enormi ignorate; ZIP AES senza pyzipper risulta unsupported; adapter usano hash/letture a budget e ZIP streama i membri; stdout/stderr CLI standard capped a 1 MiB; bitlocker2john usa il runner bounded e i candidati hanno byte budget. Restano quota disco in estrazione archive CLI, stdout/stderr BitLocker dislocker/hashcat non acquisiti ma subprocess diretti, cleanup failure e gate fixture/runtime |

### Rilievi specialistici e correzioni in corso

Audit statico read-only del 2026-10-18; le correzioni pendenti sono in lavorazione
nel worktree Git `forensic-plugin-refactor`, creato dal checkout remoto per
evitare di alterare le copie root-owned del workspace originale. Le fixture
previste restano un gate prima di dichiarare i plugin `done`.

| Plugin | Rilievo | Priorità |
| --- | --- | --- |
| `binary-static-analysis` | Corretto: warning da parser, YARA, carving e archivi ora producono `partial` | Risolta |
| `log-forensics` | Corretto: asset inline codificati a frammenti entro `byte_budget`; troncamento dichiarato `partial` | Risolta |
| `polyglot-and-embedded-content` | Corretto: flag scan legge al massimo 16 MiB per artefatto e segnala il troncamento | Risolta |
| `seganografy` | Corretto: detection del tipo usa un prefisso massimo di 1 MiB e registra la coverage parziale | Risolta |
| `encrypted-volume-forensics` | Corretto: warning di hash, filesystem e flag ora producono `partial`; fase hash disabilitata resta `skipped` | Risolta |
| `bruteforce` | Corretto: routing limitato a prefix/tail, PDF adapter bounded e scan BitLocker riservata a candidati disk-image; read/hash adapter a budget, ZIP streamato, output CLI standard limitato, bitlocker2john capped e candidati con byte budget. Restano quota disco in estrazione archive CLI, subprocess diretti BitLocker senza acquisizione output e cleanup failure | Parziale |

## Registro moduli futuri

La chiusura A3 non è stata raggiunta: i plugin legacy hanno interventi registrati,
ma restano gate di fixture, contratto e runtime. `host-artifact-forensics` è un
prototipo creato in anticipo e il suo sviluppo è differito fino alla chiusura A3.
I moduli successivi e la motivazione sono in
[roadmap del dominio forensic](FORENSIC_DOMAIN_ROADMAP.md).

| Modulo | Stato | Copertura iniziale | Debito aperto |
| --- | --- | --- | --- |
| `host-artifact-forensics` | prototipo differito | Inventario SQLite, WAL, visite/download Chromium, Firefox e Safari; inventario presenza cookie/credenziali senza valori | Sviluppo bloccato dalla sequenza A3; Registry, EVTX, artefatti Linux/macOS e app DB; fixture/runtime |
