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
4. **A3 — Gate plugin presenti:** nessuna riga `audit` o `refactor`; tutte le limitazioni
   restanti devono essere dichiarate e accettate nel registro di copertura. Solo allora
   iniziano i plugin nuovi.
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
| archive-extractor | refactor | Matcher ZIP corretto; AES/ZipCrypto distinti, cifratura e vista incompleta parziali; inventario limitato a 10.000 membri. Restano validatori e fixture |
| text-inspector | refactor | Preview limitata a 16 KiB e conteggi marcati parziali; restano offset e decodifica dichiarata |
| pic-up | refactor | Matcher limitato a stream, immagini e archivi; candidate convertite in finding/flag; accetta tutti i prefissi |
| hidgrabber | refactor | Wrapper inoltra tutti i prefissi e propaga le candidate al risultato; restano provenance frame-level e limiti dichiarati |
| githappens | refactor | Matcher per directory, archivi, immagini disco e bundle; warning/errori propagati come esito parziale. Restano limiti adapter e fixture |
| ext4atto | refactor | Warning include `mmls` mancante e soglia reale di recupero; restano limiti TSK/output da verificare |
| binary-static-analysis | audit | Trovato disallineamento: warning delle fasi non influenza `status`; file e directory del plugin sono root-owned e non modificabili dall’utente workspace, quindi il fix resta da fare dopo ripristino permessi |
| document-metadata-forensics | refactor | Matcher allineato alla validazione su file montato; input oltre byte budget ora dichiarato `partial`; restano matrice formati e gate fixture/contratto |
| polyglot-and-embedded-content | audit | 8 file test; audit confini/duplicati da svolgere |
| seganografy | audit | 3 file test; audit falsi positivi/tool opzionali da svolgere |
| log-forensics | audit | 4 file test; audit schema/regole/timestamp da svolgere |
| encrypted-volume-forensics | audit | 6 file test; audit BitLocker/provenienza chiavi da svolgere |
| bruteforce | audit | 5 file test; audit adapters/budget/segreti da svolgere |

## Registro moduli futuri

Nessun nuovo plugin deve essere implementato prima del gate A3. I moduli candidati e
la motivazione sono in [roadmap del dominio forensic](FORENSIC_DOMAIN_ROADMAP.md).
