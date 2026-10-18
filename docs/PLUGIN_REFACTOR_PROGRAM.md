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
| 5 | `githappens` | Matcher Git/directory/archive/disk specifici; distinguere errore modulo da assenza di reperti; proteggere archivio/file-system traversals; timeline e cache con origine; findings case-level limitati a 50.000 e warning a 100, con coverage e stato `partial` terminale sul flusso SSE |
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
| archive-extractor | refactor | Matcher custom attivato anche senza ragioni statiche; ZIP con local header iniziale oppure EOCD bounded con limiti e firma central-directory per SFX/ZIP vuoti, non qualunque firma incorporata; preflight EOCD/Zip64 limita l'indice centrale a 4 MiB prima del parsing; AES/ZipCrypto distinti e AES malformato resta unsupported invece di essere classificato come ZipCrypto; flag strong encryption e central directory cifrata non vengono classificati come ZipCrypto; traversal POSIX/Windows e symlink rifiutati prima di routing directory/cifratura; cleanup rimuove solo output creati dal tentativo e preserva file preesistenti; inventario 10.000 con provenienza/offset relativo allo scope archivio e stato per directory, estratti, cifrati, rifiutati o falliti; artefatti propagano source_offset_scope al core; nomi UI limitati con hash e indicatore di troncamento; il cap di 64 derivati non interrompe l'inventario dei membri esclusi; warning deduplicati e riepilogati entro 100; membri max 16 MiB e ratio 1.000:1; CRC e SHA-256 per gli estratti; budget cumulativo addebitato solo per i derivati validati e conservati. Restano fixture ZIP64/AES, casi Windows/Unicode, validatori e verifica runtime |
| text-inspector | refactor | Preview max 16 KiB con decoder BOM UTF-8/16/32, serializzazione inline progressiva (byte inline mantenuti raw), conteggi/hash su max 64 MiB e copertura parziale; tabelle di righe e offset assoluti byte max 200 con stato parziale visibile se le righe restanti sono omesse o il testo riga è abbreviato; inventario Unicode invisibile/control sull'anteprima max 100; offset Unicode omessi con sequenze invalide |
| pic-up | refactor | Matcher richiede firme PCAP/PCAPNG, immagini o archivi (WebP distinta da WAV/AVI RIFF); estensione/MIME da soli non selezionano; scanner TShark/capinfos/file bounded per output e timeout, massimo 100.000 righe/query; output TShark totale max 64 MiB per analisi, contabilizzato nelle metriche; export inventariati/hashati entro 10.000 file/64 MiB e scan contenuti export entro budget; troncamento raw non-PCAP e log allegati ora propagati a warning/partial; artefatti da comandi interrotti marcati incompleti/esclusi, ogni diagnostica rende `partial`; artefatti collegati alla fonte registrata dal parser e all'asset genitore; budget globali legacy ripristinati in `finally` e protetti da lock per evitare leakage/race tra analisi. Restano limiti globali delle liste/stream derivati e fixture |
| hidgrabber | refactor | Wrapper inoltra tutti i prefissi e propaga candidate; deduplica per frame, bus, dispositivo, endpoint e transfer type; TShark limitato per tempo/byte/righe e terminato per gruppo processo; hash core riusato; `capinfos` opzionale mentre TShark è richiesto; export artefatti limitati al budget e con asset genitore/contesto/SHA-256; report JSON duplicato disattivato nell'adapter; il testo del layout selezionato mappa intervalli Unicode a frame/timestamp/canale/tasto e aggiorna la mappa con Backspace/Alt-code; i match conservano occorrenze e intervalli sorgente. Restano gate fixture/runtime e mapping a livello di tasto per le decodifiche annidate |
| githappens | refactor | Matcher per directory, archivi, immagini disco e bundle; copia input limitata, output derivati max 64/budget; anteprima testuale legge max 2 MiB con troncamento visibile; estrazione ricorsiva streaming con budget cumulativo da 256 MiB; materializzazione virtuale limitata a 512 MiB e 300 s; scanner, decompressione, History, Slack, cache SQLite, Git oggetti, reference diff e capture subprocess con cap di byte/record/percorso e warning parziali; fallback loose-Git enumera al massimo 50.000 entry e decomprime a blocchi da 64 KiB con cap 16 MiB/oggetto, scarta symlink e segnala oggetti rifiutati/inventario troncato; l'avviso di limite findings ora contribuisce a `warning_coverage.omitted` se il registro warning è già pieno; inventory Git/refs/commit/tree e letture blob tracciati, output comandi riepilogato entro 2.000 righe con preview e `command_coverage`, fallback senza Git sempre `partial`; tree corrente letto una volta e percorsi storici raccolti con un solo comando invece di un subprocesso per commit; warning/errori/stati parziali e coverage annidati propagati nel risultato directory. Restano copertura fixture e verifica dei percorsi pipeline |
| ext4atto | refactor | Matcher immagine/partizioni; query risultati limitate, anteprima legge 2 MiB e riusa hash indicizzati; hash dell'asset core riusati per evitare seconda lettura completa della sorgente; stdout/stderr TSK bounded, recupero inode e blocchi capped e contabilizzati in un budget output cumulativo di max 512 MiB; budget visibile nelle metriche; errori e comandi TSK mancanti diventano warning; warning engine deduplicati e limitati a 100 con `warning_coverage`; `srch_strings` saltato per budget output ora abilita il fallback a blocchi senza addebitare una lettura non eseguita; 7z/PDF estratti per-member su output limitato, espansione ricorsiva con timeout globale; scansione flag artefatti a blocchi da 1 MiB, max 64 MiB/10.000 finding, copertura e warning `partial` registrati nell'artefatto/report; export ZIP su spool e cap 64 MiB/50.000 entry, symlink esclusi, superamento restituisce HTTP 413; artefatti legati all'asset genitore e al percorso filesystem/offset assoluto quando noto; flag scansionate in artefatti conservano offset relativo con scope `artifact` senza confonderlo con l'offset disco; log esposti dal plugin limitati agli ultimi 1.000 record e campi raw_output a 4.096 caratteri con omissioni visibili; endpoint log paginato con total; MIME `file` bounded; immagini virtuali dirette o compresse formattate tramite `qemu-img info`, formato QEMU verificato, backing file rifiutati e output convertito limitato; RAW gzip/xz/zstd e segmenti limitati; E01 con ewfexport; rimosso il `chmod` sull'input raw. Fixture/runtime ancora aperti |
| binary-static-analysis | refactor | Warning di coverage; entropy/string limits e input parziale espliciti; YARA limitato a prefisso 64 MiB; disassembly su regioni eseguibili entro byte budget, max 4 MiB cumulativi/10 s/20.000 istruzioni, limiti o Capstone assente marcano partial; tool runner drena output a flusso con cap runtime/byte e troncamenti rendono partial; evento timeline di carving/embedded rispecchia i warning della fase; versione interrogata solo per tool opzionali invocati; la sezione firme è `partial` solo se la scansione/input è incompleta e mostra l'intero inventario respinto entro il cap di 4.096 |
| document-metadata-forensics | refactor | Matcher allineato; source size separata dalla vista; hash dell'intero input distinto dall'hash del prefisso osservato; parser ZIP/OOXML preflight max 4 MiB/20.000 voci, inventario max 5.000 e decompressione a flusso max 16 MiB/membro e 64 MiB totali; regex custom con timeout e limiti testo/contesto; decoder payload limitato a 2.000 candidati, 1.000 output e 16 MiB cumulativi, con partial al cap; controlli hidden-content su testo invisibile/whitespace dichiarano partial e byte osservati oltre 8 MiB, firme embedded cercate sull'intero buffer concesso; offset zero-width espresso in byte sorgente anche in presenza di caratteri UTF-8 multibyte |
| polyglot-and-embedded-content | refactor | Flag scan artefatti bounded e parzialità dichiarata anche per vista importata incompleta; decoder gzip/zlib con max output reale, totale 32 MiB e 2.000 tentativi; offset flag distingue input, artefatto e payload decodificato (senza fingere una mappatura lineare); hash artefatto collegato; cap 256 flag produce warning, stato sezione ed evento parziale; ambito decoder limitato a 16 MiB e XOR a 64 KiB espone byte esaminati, warning e stato payload partial; restano confini/duplicati e fixture |
| seganografy | refactor | Type detection artefatti limitata a 1 MiB; fasi in memoria limitate a 64 MiB con coverage `partial` quando la vista concessa è più ampia; euristiche text/Unicode/whitespace su max 8 MiB con moduli/eventi partial; inventario testuale capped a 100.000 linee, 250.000 parole, 128 match HTML/strutturati con valori max 4.096 caratteri e omissioni dichiarate in metriche e sezione partial; inventari Unicode sospetti/mixed-script max 10.000, simboli 100.000, viste derivate max 100.000 codepoint con contatori omissioni e stato parziale; zTXt e decoder gzip/zlib capped con stato parziale; subprocess stdout/stderr streaming bounded; video frames/audio con byte/artifact cap e output budget condiviso; timeout/troncamento propagati a warning/partial. Restano falso positivi, coverage per formato e fixture |
| log-forensics | refactor | Directory/file e contenitori compressi letti entro budget con espansione limitata; export journal binari capped per singolo tool e a 64 MiB totali/job; prefissi export parsabili conservati, truncation/timeout/budget esaurito rende partial; output eventi/decoder clamp; entity extractor si arresta entro 5.000 per evento/100.000 totali con stato parziale e conteggio eventi successivi non letti; identity riusa hash core e fallback hash streama solo entro byte budget con scope/completo espliciti; regole Sigma solo locali, file max 256 KiB, inventory 1.000 regole/10.000 directory, max 128 selection per regola, valutazione max 10.000 eventi, 2.000.000 coppie e 5.000.000 confronti campi, match max 1.000/rule con conteggio totale; i cap generano warning e partial; inline partial visibile |
| encrypted-volume-forensics | refactor | Hash core MD5/SHA-1/SHA-256 riusati per evitare seconda lettura completa dell'immagine; ogni warning e vista importata parziale producono `partial`; hash disabilitato esplicitamente risulta `skipped`; byte/output/workspace e opzioni di scansione normalizzati entro limiti documentati, input malformato usa default e budget zero resta una scansione parziale; flag scan dichiara se il prefisso letto è incompleto; VHD/VHDX ispezionati con qemu-img, formati interni coerenti richiesti, backing file esterni rifiutati e raw temporaneo promosso solo se dimensione coincide; split RAW richiede sequenza regolare senza lacune, inventario bounded e merge atomico; tool runner standard usa cap stream/tempo e, per conversione qemu-img e figli recovery, RLIMIT_FSIZE e umask privato via exec-helper senza `preexec_fn`; launcher John/Hashcat hanno timeout cumulativo, massimo 32 wordlist e file recovery capped a 16 MiB; inventario pytsk3 con deque O(1), cap immediato di entry, warning coverage per file esclusi e budget residuo controllato prima della lettura; artefatti registrano separatamente `password_verified` e `key_verified`; export libbde incompleti rimossi su errore e limiti tool presenti prima di costruire sezione warning; artifact deduplicati e registrati mantengono fino a 100 percorsi/inode sorgente distinti, con ID e nomi file basati sullo SHA-256 completo. Restano gate fixture/runtime |
| bruteforce | refactor | Matcher bounded; inventory wordlist budgetato e righe enormi ignorate; anno delle trasformazioni fissato per run e riportato nell'audit; ZIP AES senza pyzipper risulta unsupported; adapter usano hash/letture a budget e ZIP streama i membri; archivi 7z/RAR inventariati entro 4 MiB/10.000 membri ed estratti un membro alla volta su file generati con quota cumulativa applicata durante la scrittura; dislocker-file/hashcat/bitlocker2john passano dal runner con cap di stream, timeout e RLIMIT_FSIZE dove disponibile; qpdf, Steghide, OpenStego e GPG applicano RLIMIT_FSIZE ai file decifrati prima dell'avvio, Office e pikepdf scrivono tramite wrapper file seekable a quota; i probe GPG/OpenStego/Steghide sono rimossi ad ogni tentativo, gli artefatti finali sono estratti dopo verifica separata, e stdout troncato di StegCloak non conta come password valida; BitLocker chiude le viste anche se l'apertura libbde fallisce, non avvia Hashcat su output bitlocker2john non riuscito e limita linea hash/lettura segreto; fallimenti extraction diventano warning `partial`; stdout/stderr capped e candidati hanno byte budget. Restano gate fixture/runtime e verifica compatibilità del wrapper con le librerie opzionali |

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
| `bruteforce` | Corretto: routing limitato a prefix/tail, PDF adapter bounded e scan BitLocker riservata a candidati disk-image; read/hash adapter a budget, ZIP streamato, estrazione 7z/RAR per membro con quota output durante la scrittura e cleanup degli output incompleti, BitLocker usa runner con stream capped, input password da stdin e output file limitato dove supportato; lo stato `cancelled` viene propagato e non genera un finding di password fallita. Restano gate fixture/runtime e verifica cross-platform del limite file | Parziale |

## Registro moduli futuri

La chiusura A3 non è stata raggiunta: i plugin legacy hanno interventi registrati,
ma restano gate di fixture, contratto e runtime. `host-artifact-forensics` è un
prototipo creato in anticipo e il suo sviluppo è differito fino alla chiusura A3.
I moduli successivi e la motivazione sono in
[roadmap del dominio forensic](FORENSIC_DOMAIN_ROADMAP.md).

| Modulo | Stato | Copertura iniziale | Debito aperto |
| --- | --- | --- | --- |
| `host-artifact-forensics` | prototipo differito | Inventario SQLite, WAL, visite/download Chromium, Firefox e Safari; inventario presenza cookie/credenziali senza valori | Sviluppo bloccato dalla sequenza A3; Registry, EVTX, artefatti Linux/macOS e app DB; fixture/runtime |
