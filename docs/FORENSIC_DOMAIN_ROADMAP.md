# Copertura del dominio forensic e piano di sviluppo

Aggiornato: 18 ottobre 2026. È una valutazione della codebase presente, non una
certificazione del prodotto né una dichiarazione di completezza. “Parziale” significa
che esiste almeno un parser o flusso utile, con formati, fonti o verifiche mancanti.

## Stato della suite

Il prodotto è un hub locale con casi, acquisizione file/testo/directory, hashing,
triage, job isolati, artefatti derivati, workflow DAG, API e renderer dichiarativi.
Il registro plugin è estendibile dai manifest. La suite include componenti per dischi
e filesystem, file/binari/firmware, archivi e contenuti embedded, documenti e metadata,
steganografia, PCAP/USB HID, log, Git e recupero password limitato.

Questa ampiezza non copre il dominio forensic nel suo complesso. La suite attuale è
principalmente un laboratorio locale di analisi statica e triage; non è uno strumento
universale di acquisizione certificata, mobile, cloud o live response.

## Matrice di copertura

| Area | Stato | Presente | Lacune da colmare |
| --- | --- | --- | --- |
| Casi, upload, hash, provenienza | Parziale | Hash multipli, asset immutabili, parent/derivati, audit di riparazione | Catena di custodia completa, operatori, tempi e timezone dell'acquisizione, fonte/strumento/versione, firme dei manifest, export verificabile |
| Dischi e filesystem | Parziale | Partizioni, FAT/EXT e integrazione Sleuth Kit/Ext4atto, carving | NTFS/APFS/HFS+/XFS/Btrfs e filesystem embedded con copertura dichiarata; journal, slack, file cancellati e sparse extent; immagini segmentate/forensi più ampie |
| Memoria volatile | Mancante | Il tipo `memory_dump` è accettato da alcuni plugin generici | Plugin dedicato a Volatility 3 e simboli, processi/moduli/connessioni/handle, timeline e dipendenze versionate |
| Mobile | Mancante | Nessun parser iOS/Android dedicato | Backup iTunes/iOS, Android backup/ADB e filesystem extraction, SQLite/WAL, artifact timeline, limiti legali e acquisizione esplicita |
| Sistemi operativi e host | Parziale | Analisi log generica e alcune integrazioni di recupero | Windows Registry/EVTX/Prefetch/Amcache/USN, macOS Unified Log/Plist/FSEvents, Linux journald/auth/audit, artefatti browser e persistenza |
| Browser | Mancante | I database possono essere caricati come file generici | Chrome/Chromium, Firefox, Safari; SQLite/WAL, download, cookie/sessioni, cache, profili e normalizzazione timeline |
| Email e messaggistica | Mancante | Nessun plugin mailbox | EML/MBOX/PST/OST, header, MIME, allegati, thread, timezone, deduplica e chat export |
| Rete | Parziale | PCAP tramite pic-up, HID USB e analisi di flussi disponibili | Parser/protocolli e TCP stream dichiarati, DNS/HTTP/TLS, canali covert, NetFlow/Zeek, correlazione multi-cattura |
| Log e incident response | Parziale | Plugin log con normalizzazione, regole e timeline | Copertura schema/fonti, SIEM import, Sigma testata, regole versionate, correlazione multi-host e quality score |
| Documenti e media | Parziale | Metadata, PDF/documenti e tecniche stego selezionate | Formati/versioni, firme e validazione strutturale più profonde, OCR opzionale, audio/video, camera RAW e provenienza delle trasformazioni |
| Malware e reverse engineering | Parziale | Parsing statico ELF/PE/Mach-O, stringhe e disassembly limitato | Threat intel offline con fonti/versioni, YARA versionata, sandbox dinamica isolata separata, memory/config extraction per famiglie |
| Archivi e file danneggiati | Parziale | ZIP estrazione sicura e carving/embedded | TAR/7z/RAR e formati cifrati con supporto dichiarato; riparazione su copia con diff e validazione; bomb resistance e fixture avversarie |
| Crittografia e password | Parziale | Rilevamento e tentativi password/volumi selezionati | Hash format ampiamente aggiornati, gestione chiavi, formati documentali e vault; strategia esplicita per credenziali senza conservarle |
| Cloud e SaaS | Mancante | URL trattati come testo; nessun accesso di rete | Parser export AWS/Azure/GCP/M365/Google Workspace, audit trail, correlazione identità/risorsa; import esplicito, nessuna chiamata implicita al tenant |
| Database e applicazioni | Mancante | SQLite può essere analizzato come file generico | SQLite WAL/SHM, browser/app DB, LevelDB, plist, registry hive e applicazioni comuni con schema/versione |
| Visualizzazione e reporting | Parziale | Sezioni, tabelle, timeline, grafi e grafici SVG con palette controllate | Vista caso unificata, finding prioritizzati, navigazione finding→byte/record, coverage/incompletezza, timeline correlata e report firmabile |
| Acquisizione live/remota | Fuori ambito attuale | API locale, input manuale | Agenti/collector e rete non vanno aggiunti finché non esistono modello autorizzativo, autenticazione, audit, trasporto protetto e threat model |

## Problemi logici affrontati in questo intervento

- Un caso poteva essere rimosso con job in pausa o workflow ancora attivo. La verifica
  di cancellazione include ora stati `paused` dei job e tutti i workflow attivi; l'avvio
  del workflow è serializzato con la cancellazione del caso.
- L'acquisizione rileggeva e decodificava tutti i record asset per contare oggetti e
  byte. La quota ora usa una query aggregata SQLite.
- I matcher custom in sandbox venivano riavviati più volte sullo stesso asset immutabile.
  La decisione è memorizzata in una cache LRU limitata a 4.096 coppie plugin/asset.

Questi cambiamenti riducono lavoro ripetuto, ma non trasformano i parser parziali in
copertura completa. Il database locale, i report e le wordlist personali non fanno
parte del repository.

## Contratto comune per moduli e plugin

Ogni plugin deve dichiarare `domains`, `supported_asset_types`, `capabilities`,
dipendenze, timeout, byte budget e strumenti opzionali nel manifest. Non si estendono
`if/else` centrali per ogni formato. Il parser resta isolato; il core gestisce casi,
job, limiti, provenienza, artefatti e presentazione.

I risultati dovrebbero convergere su queste entità condivise:

- **Finding:** titolo, severità, stato (osservato/candidato/validato), confidenza,
  spiegazione, asset sorgente, offset/record, fase, limiti e riferimenti agli artefatti.
- **Timeline event:** istante UTC, timestamp originale, timezone o precisione nota,
  tipo evento, entità, asset e posizione sorgente.
- **Entity:** ID stabile nel caso, tipo, valore normalizzato, fonti e relazioni.
- **Artifact:** hash, padre, metodo/strumento/versione, byte range e validazione.
- **Coverage:** fonti analizzate, parser effettivamente avviati, budget/troncamenti,
  dipendenze assenti e ragioni per cui un dominio è rimasto non esaminato.

Il core deve mantenere separati `nessun riscontro` e `analisi incompleta`. Nessuna
flag o assenza di flag deve essere presentata senza la provenienza del rilevamento.

## Piano di lavoro

### Fase 0 — Affidabilità e riduzione del costo (in corso)

1. Eliminazione sicura dei casi con run attivi e stato coerente alla ripartenza.
2. Ridurre scansioni DB ripetute e processi matcher ridondanti.
3. Misurare CPU, tempo e memoria su casi piccoli, medi e grandi; distinguere costi UI,
   serializzazione e plugin.
4. Definire payload di risultato e vocabolario finding/coverage/timeline.

### Fase 1 — Strato probatorio e vista grafica coerente

1. Aggiungere hash/manifests di acquisizione firmabili, audit append-only e campi fonte.
2. Standardizzare finding, entità, timestamp e coverage mantenendo compatibilità con
   i risultati plugin esistenti.
3. Fare della schermata caso un riepilogo con: esito, completezza, finding prioritari,
   timeline, asset/relazioni e dipendenze mancanti.
4. Ogni valore in tabella/grafico deve portare al record o byte sorgente; ogni grafico
   ha unità, legenda, filtro e una vista tabellare accessibile equivalente.

### Fase 2 — Maggiore riuso dei dati e formati host

1. SQLite/WAL, browser, Windows Registry/EVTX e artefatti Linux/macOS.
2. Correlazione multi-asset per identità, host, sessione e tempo.
3. Migliorare NTFS e copertura di journal/slack/cancellati con strumenti dichiarati.
4. Aggiungere parsing email e mailbox.

### Fase 3 — Moduli specialistici isolati

1. Memoria con Volatility 3 e pacchetto simboli verificabile.
2. Mobile tramite import di backup/export, senza acquisizione implicita dal dispositivo.
3. Cloud tramite export offline e schemi versionati.
4. Ampliare protocolli rete, timeline di flusso e decoder di canali covert.
5. Formati hash, riparazione archivi su derivato e analisi di database applicativi.

### Fase 4 — Maturità operativa

1. Threat model, campagne fuzz per parser esposti e fixture pubblicabili senza dati reali.
2. Reproducibility manifest: versione suite/plugin/tool, config, hash input e limiti.
3. Import/export caso, report e audit verificabili; backup/retention configurabili.
4. Valutare separatamente multiutente/remoto, collector live e integrazioni con servizi.

## Criteri per dichiarare una copertura

Per ogni formato o fonte pubblicare: versioni supportate, acquisition path, parser e
versioni, fixture positive/negative/malformate, limiti, comportamento su input
troncato, campo probatorio citabile e costo misurato. Registrare gli esiti in una
matrice formato × funzionalità (`identify`, `parse`, `recover`, `timeline`, `validate`).
Una riga è “supportata” solo per le funzioni davvero verificate; non inferire da una
estensione o da un match di firma che l'analisi sia completa.
