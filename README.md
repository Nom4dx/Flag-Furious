# Forensic Hub

Workspace web locale per analizzare asset attraverso plugin autonomi. Backend FastAPI,
contratti Pydantic, persistenza SQLite, frontend JavaScript/SVG senza build e senza
connessioni esterne. Interfaccia in italiano, nero predominante e dettagli bianchi, font Barlow e IBM Plex Mono.
Gli output dei plugin sono organizzati in gruppi e sezioni tramite un
[engine di presentazione JSON dichiarativo](docs/OUTPUT_MAPPING.md), con tabelle
ricercabili, valori formattati e dettagli espandibili.

La suite copre diversi flussi di triage, ma non tutto il dominio forensic. La
[matrice di copertura e roadmap](docs/FORENSIC_DOMAIN_ROADMAP.md) distingue ciò che è
presente, parziale e mancante. La skill di progetto per valutare o aggiungere capacità
è in [`.agents/skills/forensic-domain/SKILL.md`](.agents/skills/forensic-domain/SKILL.md).
Il rifacimento dei plugin esistenti e il gate prima dei moduli nuovi seguono il
[programma di sviluppo](docs/PLUGIN_REFACTOR_PROGRAM.md).

## Avvio

Richiede **Linux, Python 3.11+ e bubblewrap** con user namespace disponibili. Non avviare
il servizio con privilegi elevati. Il bind predefinito è esclusivamente `127.0.0.1`.

Dopo aver installato le dipendenze, l'avvio ordinario usa lo script nella root:

```bash
./start.sh
```

Lo script usa automaticamente `.venv`, carica un eventuale `.env`, evita di avviare
una seconda istanza sulla stessa porta e apre il browser. Per un server senza desktop:
`./start.sh --no-browser`; per cambiare porta: `./start.sh --port 8080`.

```bash
# Debian / Ubuntu, se bubblewrap non è già installato
sudo apt install bubblewrap
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app
```

Il comando attende che l'API sia pronta e apre `http://127.0.0.1:8000` nel browser.
Per host senza desktop: `python -m app --no-browser --port 8000`.
La specifica OpenAPI è disponibile su `/openapi.json`, il riferimento leggibile su
`/docs`. Non servono npm, CDN o servizi remoti per usare l'interfaccia.

Le variabili descritte in `.env.example` possono essere esportate nell'ambiente del processo
oppure salvate in `.env`, che `start.sh` carica automaticamente. È previsto **un solo processo Uvicorn**:
i job usano una coda locale con due worker e checkpoint SQLite.

## Tool preservati e integrazione

Le integrazioni riusano componenti forensic esistenti e ne registrano le copie,
destinazioni e SHA-256 in [`docs/source-inventory.json`](docs/source-inventory.json).

| Componente | Integrazione | Dipendenze |
| --- | --- | --- |
| Magic Wrapper | Core file-only, codice originale in `app/vendor/magic_wrapper`, adapter in `app/core/magic_wrapper.py` | Python; ExifTool opzionale |
| Ext4atto | Plugin che esegue `diskhunt.Analyzer`, mantiene parser filesystem, recupero, carving e risultati | zstandard, pydantic-settings; Sleuth Kit, qemu-img, ewfexport opzionali |
| GitHappens | Plugin che esegue la pipeline originale per file/archivi e i moduli Git/cache/history/Slack sulle directory | Git, qemu-img, tsk_recover, 7z opzionali |
| HIDGrabber | Plugin che esegue il decoder USB HID originale e registra gli output | tshark, capinfos |
| pic-up | Plugin che esegue il triage e il carving originali attraverso la loro configurazione CLI | tshark per catture; altri tool dichiarati nel manifest |
| Text Inspector | Esempio generale per testo, JSON, hex e URL testuali; distribuzione byte via JSON | Nessuna aggiuntiva |
| Archive Extractor | Estrazione ZIP con verifica CRC, rifiuto traversal/symlink e budget cumulativo; input troncati esplicitati | Nessuna aggiuntiva |
| Document Metadata Forensics | Metadata e struttura passiva di documenti, immagini, PDF, Office/OLE/RTF, timeline e payload | ExifTool, pdfinfo, pdftotext e olevba opzionali |
| Polyglot & Embedded Content | Firme streaming, validator strutturali, confini, polyglot/SFX, carving, ZIP sicuri, decoy, payload e grafo di estrazione | 7z e unrar opzionali; nessuna dipendenza obbligatoria |

I tool opzionali mancanti compaiono nel registro plugin. Le dipendenze non vengono
installate automaticamente durante il caricamento. Un import fallito, un manifest
invalido, un ciclo di dipendenze o un requisito obbligatorio mancante disabilita il
singolo plugin e lascia disponibile l'hub. Il core non enumera domini o categorie:
`domains` e `supported_asset_types` sono stringhe estendibili nel manifest.

Magic Wrapper comprende l'adapter e i file sorgente necessari alla sua integrazione.
I dettagli sui componenti e sulle relative limitazioni sono registrati nei manifest e
nella documentazione dei plugin.

## Flusso di lavoro

1. Crea un caso oppure carica direttamente un asset: il caso viene creato dal frontend.
2. Scegli file multipli, una directory, testo, hex, JSON, URL testuale o un tipo personalizzato.
3. Acquisisci hash e metadati, confronta un hash atteso opzionale e consulta il triage file.
4. Seleziona asset e plugin compatibili. Una lista vuota di plugin esegue solo le fasi core;
   tramite API `plugin_ids: null` seleziona tutti i plugin compatibili.
5. Segui grafo, fasi, comandi, log, flag, tabelle, grafici e artefatti.
6. Gli asset derivati mantengono padre, hash e provenienza; la ricorsione invoca
   automaticamente i plugin compatibili fino ai limiti configurati.
7. Scarica il report JSON o HTML autosufficiente. L'HTML può essere stampato in PDF.

Le directory vengono acquisite come manifest con elenco canonico di percorsi relativi,
dimensioni e SHA-256 dei file. Il loro SHA-256 identifica tale elenco; i figli hanno
anche gli hash del contenuto. Il worker riceve una vista read-only della directory.
Non vengono accettati percorsi arbitrari del filesystem server tramite API.

Il grafo permette zoom con rotella o pulsanti, pan sullo sfondo, selezione da tastiera,
filtri per plugin/stato, esclusione delle fasi interne, focus su plugin, evidenziazione
degli antenati del nodo e export JSON/SVG. Un clic apre output, asset o artefatto.
I grafici hanno selezione, tooltip, filtro dati, zoom/pan ed export SVG. Le sezioni
sono ordinate e tipizzate dal file `output_schema.json` del plugin.

## Magic Wrapper

L'adapter richiama il database, i matcher con wildcard/offset, i validatori strutturali,
il parser EXIF e la riparazione del tool originale. Hash a blocchi: MD5, SHA-1,
SHA-224/256/384/512, SHA-3, SHAKE, BLAKE2b/BLAKE2s e algoritmi disponibili nel runtime
(SM3, RIPEMD160, Whirlpool, MD4). Gli algoritmi non disponibili sono elencati separatamente.
Gli hash SHAKE usano 32 byte di output, come nel wrapper originale.

L'adapter restituisce tutte le firme compatibili nei limiti configurati: offset,
prova, provenienza, affidabilità e distinzione tra firma candidata e validazione
strutturale. Conserva i validatori PNG/7z/ZIP/PDF/JPEG/GIF/BMP/RIFF-WEBP/ELF/PE/TAR/SVG.
La scansione embedded richiede ancore di almeno quattro byte; firme di un solo byte
sono ignorate. Firme multiple non sono automaticamente prova di un poliglotta.
Le validazioni legacy sono controlli strutturali specifici, non certificazioni complete
del formato. Il CRC ZIP dei membri viene verificato durante l'estrazione ZIP.

Puoi aggiungere file JSON di firme con `HUB_SIGNATURE_FILES=/path/a.json:/path/b.json`:

```json
[
  {"pattern": "41 42 ?? 44 45", "offset": 3, "description": "Formato proprietario"}
]
```

La scansione embedded è limitata ai primi 8 MiB, a 512 risultati complessivi, 16 occorrenze
per firma e 10 secondi, oltre al budget della vista di input. Il troncamento globale è segnalato;
il limite per singola firma agisce come prevenzione dei falsi positivi e non rende parziale il triage.
Gli hash acquisiti sono sempre del file originale completo; i risultati di una vista
troncata non vengono presentati come una verifica completa.

La riparazione richiede il pulsante **Ripara copia** con conferma, oppure
`POST /api/assets/{id}/repair` con `{"confirm": true}`. Si accetta una sola struttura
riparabile non ambigua. Si valida prima e dopo, si crea un asset distinto, si registrano
byte precedenti/nuovi e hash nel caso. Non sono consentiti un percorso di output
scelto dall'utente o la sovrascrittura dell'evidenza. Una vista parziale non è riparabile.

## Isolamento e limiti

- Gli upload vengono copiati in directory per caso/asset e marcati `0400`.
- Il codice plugin non viene importato nel processo API: anche probe, matcher ed
  endpoint custom vengono eseguiti in namespace bubblewrap.
- Il worker vede runtime Python, core, una copia del proprio plugin e l'input autorizzato.
  Non vede altri casi, directory personali, segreti o configurazione del server.
- Nessun mount host è scrivibile. `/work` e `/tmp` sono tmpfs con dimensione limitata.
  Nessun mount temporaneo rimane dopo la terminazione del processo.
- Rete e privilegi sono negati. Un plugin che li richiede viene disabilitato.
  Le CLI sono invocate senza shell dai tool preservati; ogni invocazione viene
  registrata dal Python audit hook. Evidenze, macro e file recuperati non vengono eseguiti.
- Timeout con terminazione del gruppo di processi, limiti CPU, address-space, file-size
  e descriptor. I limiti CPU/memoria sono per processo; non sono una quota cgroup
  aggregata sull'intero albero di subprocessi. Per plugin deliberatamente ostili usare
  anche un contenitore/VM con cgroup e una policy di installazione controllata.
- Il **byte budget del core limita la vista di input** predefinita e la sua allocazione
  cumulativa tra analisi. I plugin che dichiarano `input_access: random_access`
  (Ext4atto) ricevono il singolo file completo, read-only e soggetto al limite upload,
  per poter leggere partizioni e inode a qualsiasi offset. Il budget limita le loro
  scansioni native, non tutte le riletture interne delle CLI. Il triage iniziale
  riserva budget ai plugin selezionati.
- Default: upload 1 GiB, evidenze per caso 4 GiB, budget core 1 GiB,
  memoria worker 1 GiB massima, timeout 120 s, 1.024 asset conservabili per caso,
  128 asset attraversabili per singolo job e profondità 3.
  Workspace temporaneo massimo 1 GiB, configurabile con `HUB_MAX_WORKSPACE_BYTES`.
  I manifest possono restringere i limiti, non superare i massimi del server.
- In modalità `bounded` un asset oltre il budget produce una vista parziale. Analisi disco estese
  richiedono una configurazione adeguata; l'assenza di una flag nella vista non prova
  che sia assente nell'intera immagine.
- Hash + ID plugin impediscono cicli e duplicazioni di esecuzione nel job. Profondità,
  numero asset, cap output e tmpfs fermano espansioni ricorsive incontrollate.
- HTML/SVG e altri contenuti attivi degli artefatti sono mostrati come testo/hex oppure
  scaricati come attachment; non vengono incorporati nel documento del frontend.
- Se bubblewrap non è disponibile, caricamento UI, casi, hashing e ricerca core
  restano accessibili; analisi plugin e triage strutturale sono dichiarati non disponibili.

Questa versione è un'applicazione locale per singolo operatore: non include account,
collaborazione multiutente, scheduler distribuito, analisi remota o accesso di rete
per plugin OSINT. Gli URL sono riferimenti testuali. Il rilevamento globale cerca nei
byte e risultati effettivamente resi accessibili dai plugin: l'accesso a slack space,
journal, file cancellati, Git e database dipende dagli estrattori e dalle CLI disponibili.
La ricerca supporta prefissi/regex, Base64, hex, URL encoding, ROT13, inverso, split,
UTF-16 e RC4 con chiave esplicita. Non include brute force di chiavi o decodifica universale.

## API essenziali

Tutti gli endpoint richiesti sono implementati, oltre a riparazione, OpenAPI e
namespace custom dei plugin. Esempio di analisi testuale:

```bash
curl -s http://127.0.0.1:8000/api/health
curl -s -X POST http://127.0.0.1:8000/api/cases \
  -H 'Content-Type: application/json' -d '{"name":"Esempio"}'
# Sostituire CASE_ID e ASSET_ID con gli ID ricevuti.
curl -s -X POST http://127.0.0.1:8000/api/assets \
  -H 'Content-Type: application/json' \
  -d '{"case_id":"CASE_ID","type":"text","content":"flag{example}"}'
curl -s -X POST http://127.0.0.1:8000/api/jobs \
  -H 'Content-Type: application/json' \
  -d '{"case_id":"CASE_ID","asset_ids":["ASSET_ID"],"plugin_ids":["text-inspector"]}'
# File: multipart, campo file oppure files, case_id obbligatorio.
curl -s -F case_id=CASE_ID -F file=@evidence.bin http://127.0.0.1:8000/api/assets
```

Casi attivi non sono eliminabili: annullare i job e attendere lo stato terminale.
I job in corso durante un riavvio vengono marcati parziali; non sono ripresi implicitamente.

## Sviluppare plugin

Leggere [`plugins/README.md`](plugins/README.md) e copiare `plugins/_template/` in una
nuova directory. Cambiare ID/classe e manifest, aggiungere la logica, quindi riavviare
l'hub. **Non è necessario modificare core, frontend o lista di domini.**

## Verifiche

```bash
pip install -r requirements-dev.txt
python -m pytest
python scripts/test_legacy.py
python scripts/verify_sources.py
# Con hub già avviato e Chromium installato:
python scripts/browser_smoke.py
```

Il test browser crea e cancella un caso di prova, verifica desktop/mobile, grafi,
flag, tutti i renderer e i colori computati; salva screenshot in `test-results/`.
Le suite originali restano separate per evitare collisioni dei loro moduli `app`
e `conftest`. Dettagli e risultati in [`docs/VALIDATION.md`](docs/VALIDATION.md).

Riferimenti architetturali: [FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/),
[bubblewrap](https://github.com/containers/bubblewrap),
[Python resource limits](https://docs.python.org/3/library/resource.html).
## Workflow di estrazione e connector

La console di ogni caso espone **Workflow estrazione**. Il pool a sinistra può
mostrare gli asset registrati nel caso oppure i connector disponibili; un doppio
clic o un drag & drop aggiunge un nodo al canvas, mentre le porte circolari creano
gli archi. I workflow sono DAG persistenti e ricaricabili. Ogni connector viene
eseguito come un normale job plugin isolato e gli asset derivati diventano input
dei nodi successivi.

I connector dichiarativi risiedono in `connectors/<id>/connector.json`. Il core
espone automaticamente come connector anche i plugin che dichiarano capacità di
estrazione, carving, recupero, payload o produzione di asset derivati. Sono inclusi
`bruteforce`, per tentativi limitati con wordlist, e `known-password`, per una
password già nota. I campi elencati in `secret_fields` non vengono salvati nel
workflow: sono inviati solo alla singola esecuzione, mascherati nel job e cancellati
dalla memoria del worker al termine.

API disponibili: `GET /api/connectors`, CRUD sotto `/api/workflows`, esecuzione con
`POST /api/workflows/{id}/run` e stato sotto `/api/workflow-runs/{id}`.
