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
4. **A3 — Gate iniziale plugin presenti:** nessun plugin deve restare in `audit`; ogni
   plugin esistente deve avere almeno un miglioramento concreto di limiti, matcher,
   copertura o presentazione e i rilievi alti devono essere risolti o registrati come
   bloccati. I gate di fixture/validazione restano `refactor` finché non sono eseguiti;
   questo debito non va nascosto né scambiato per copertura verificata. Superato il gate
   iniziale, B1 può partire mentre le verifiche dei plugin continuano in parallelo.
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
| hidgrabber | refactor | Wrapper inoltra tutti i prefissi e propaga le candidate; diagnostics e input troncato producono `partial`; restano provenance frame-level e limiti dichiarati |
| githappens | refactor | Matcher per directory, archivi, immagini disco e bundle; warning/errori propagati come esito parziale. Restano limiti adapter e fixture |
| ext4atto | refactor | Warning include `mmls` mancante e soglia reale di recupero; restano limiti TSK/output da verificare |
| binary-static-analysis | refactor | `status=partial` ora riflette warning delle fasi e copertura incompleta; restano gate di fixture/contratto e matrice verificata formati/tool |
| document-metadata-forensics | refactor | Matcher allineato alla validazione su file montato; input oltre byte budget ora dichiarato `partial`; restano matrice formati e gate fixture/contratto |
| polyglot-and-embedded-content | refactor | Flag scan degli artefatti derivati bounded e parzialità esplicita; restano confini/duplicati e gate fixture/contratto |
| seganografy | refactor | Detection del tipo artefatto limitata a 1 MiB e partial dichiarato; restano falsi positivi/tool opzionali e gate fixture/contratto |
| log-forensics | refactor | Asset inline limitato e parzialità visibile; restano schema/regole/timestamp e gate fixture/contratto |
| encrypted-volume-forensics | refactor | Ogni warning di copertura produce `partial`; hash disabilitato esplicitamente risulta `skipped`; restano matrice BitLocker e gate fixture/contratto |
| bruteforce | refactor | Matcher da 64 MiB ridotto a campione prefix/tail; PDF e Office adapter senza letture massive/ripetute; restano matrice adapter/limiti e gate fixture/contratto |

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
| `bruteforce` | Corretto: routing limitato a prefix/tail, PDF adapter bounded e scan BitLocker riservata a candidati disk-image | Risolta |

## Registro moduli futuri

Il gate iniziale A3 è stato superato: tutti i plugin presenti hanno un intervento
concreto registrato; i test/fixture non eseguiti restano visibili in stato `refactor`.
Il primo modulo nuovo in sviluppo è `host-artifact-forensics` (SQLite/WAL e cronologia
browser offline). I moduli successivi e la motivazione sono in
[roadmap del dominio forensic](FORENSIC_DOMAIN_ROADMAP.md).

| Modulo | Stato | Copertura iniziale | Debito aperto |
| --- | --- | --- | --- |
| `host-artifact-forensics` | in sviluppo | Inventario SQLite, WAL, visite/download Chromium, Firefox e Safari; inventario presenza cookie/credenziali senza valori | Registry, EVTX, artefatti Linux/macOS e app DB; fixture e verifica runtime |
