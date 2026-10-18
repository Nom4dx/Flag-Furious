# Contratto plugin Forensic Hub

Un plugin è una directory indipendente con `plugin.json`, `extensions.json`,
`output_schema.json` e l'entrypoint Python. Le sottodirectory `src/`, `assets/`,
`tests/` e ogni altro modulo sono permesse. `_template/` viene ignorata dal loader.
I plugin installati sono codice fidato dall'operatore, eseguito comunque in isolamento.

## Manifest e import

Il manifest usa i campi del modello `app.models.contracts.Manifest`: ID univoco,
nome, versione, autore, descrizione, entrypoint e `class`, domini liberi, tipi asset,
capacità, dipendenze, timeout, CPU, memoria, byte budget e output budget. Vedere
`_template/plugin.json`. `dependencies` sono ID di altri plugin; `python_dependencies`
sono nomi importabili e `binaries` sono CLI obbligatorie. `optional_binaries` genera
warning informativi. Non viene eseguito `pip install` dal loader.

L'entrypoint viene importato come `hub_plugin.entrypoint`, così sono supportati
import relativi (`from .src.parser import parse`). `/plugin`, `/plugin/src` e
`/plugin/src/backend` sono nel path Python del worker. Le dipendenze vanno installate
nello stesso ambiente dell'hub. Tutti i file del plugin devono essere regolari:
symlink, percorsi che escono dalla directory, manifest oltre 1 MiB e plugin oltre
256 MiB/10.000 file vengono rifiutati.

Il caricamento avviene in due fasi: validazione dati nel core, probe dell'import e
costruzione dell'istanza in un worker. Anche un errore nell'import resta isolato.
`requires_root`, `requires_network` e permessi aggiuntivi sono riconosciuti ma negati
dalla policy locale. `execution_mode` è `isolated`.

## Compatibilità

`extensions.json` può dichiarare `extensions`, `mime_types`, `magic_bytes` (hex string
oppure `{"pattern":"514649fb","offset":0}`), `asset_types`, `content_signatures`,
`regex`, `keywords`, `json_schema`, `encodings`, `protocols`, `content_types`,
`attributes` e `custom_matcher: true`. I matcher dichiarativi sono in OR, dopo il
controllo dei tipi supportati. `attributes` richiede tutte le coppie chiave/valore.
Per wildcard complesse o struttura specifica implementare `can_handle`.

I matcher regex hanno un timeout. `can_handle` riceve una vista limitata a 64 KiB e
ritorna `compatible`, `score` tra 0 e 1, `reasons` come lista di stringhe. Non leggere
l'intero file durante la proposta: l'analisi completa appartiene ad `analyze`.
Una semplice estensione è un indizio, non prova del formato.

## Metodi

Estendere `app.core.plugin.BasePlugin`:

```python
from pathlib import Path
from app.core.plugin import BasePlugin

class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        return {"compatible": asset["type"] == "text", "score": 1,
                "reasons": ["Testo strutturato"]}

    def validate(self, asset, context):
        return {"valid": True}

    def analyze(self, asset, context, reporter):
        reporter.phase("Parsing")
        reporter.log("Lettura della vista autorizzata")
        with Path(asset["path"]).open("rb") as source:
            data = source.read(context["byte_budget"])
        return {
            "summary": "Parsing completato", "confidence": 1,
            "sections": [{"id": "summary", "data": {"bytes": len(data)}}],
            "visualizations": [{"type": "bar", "title": "Conteggi",
                "data": [{"x": "byte", "y": len(data)}]}],
            "metrics": {"bytes_read": len(data)}
        }
```

Gli altri metodi hanno implementazione vuota: `extract_artifacts`, `create_assets`,
`create_visualizations`, `search_flags`, `cleanup`. Vengono invocati dal worker.
`cleanup` è eseguito nel `finally`; in caso di SIGKILL il namespace distrugge comunque
i mount temporanei. Non effettuare mount host o modifiche persistenti nell'import.

Il contesto include `output_dir` (`/work`), `byte_budget`, `output_bytes`, prefissi,
modalità e risultati delle dipendenze. `asset.path` è read-only e può essere una vista
parziale: controllare `partial_input` e `visible_bytes`. Gli asset JSON hanno anche
`content`; gli asset directory espongono un albero read-only. Gli URL non vengono visitati.

## Output, artefatti e streaming

L'output è validato da `Result`: summary, status, confidence, findings, sections,
artifacts, derived_assets, visualizations, flags, timeline, execution_events, logs,
warnings, errors, metrics, requested_plugins. `plugin_id` e `asset_id` sono attribuiti
dal core. Status ammessi: completed, partial, failed, cancelled, skipped.

Per ogni finding includere prova, offset (o null se sconosciuto), source, confidence,
phase ed eventuale command. Non rappresentare un candidato come struttura validata.

Per produrre un file scriverlo sotto `/work` e restituire una descrizione:

```python
output = Path(context["output_dir"]) / "decoded.txt"
output.write_text("testo ricostruito")
return {"summary": "Estratto", "derived_assets": [
    {"path": str(output), "name": "decoded.txt", "offset": 64,
     "method": "decoder", "confidence": 0.8}
]}
```

Per dati strutturati: `{"name":"decoded.json","type":"json","content":{"a":1}}`.
Gli artefatti e i derivati diventano asset del caso; non duplicare lo stesso file in
entrambe le liste. Il worker esporta solo file regolari in `/work` e trasferisce i
byte attraverso IPC JSON limitato. Il processo API assegna gli ID, salva, calcola hash
e costruisce la provenienza. Nessun percorso arbitrario del plugin viene usato dal core.

`reporter.log(message, level="info", command=None)`, `reporter.phase(name, **metadata)`,
`reporter.partial(result)` e `reporter.visualization(spec)` pubblicano eventi JSONL
incrementali, consultabili durante l'esecuzione. `analyze` può essere un generatore
che emette dizionari parziali; il risultato finale è l'accumulo dei dizionari emessi.
`requested_plugins` contiene ID di plugin compatibili da accodare; le dipendenze sono
eseguite in ordine topologico. Hash/ID, profondità, numero asset e budget impediscono cicli.

## Sezioni e visualizzazioni

`output_schema.json` dichiara ID, titolo, tipo e ordine. Le sezioni restituite da
`analyze` forniscono `id` e `data`. Lo schema è autorevole su titolo/tipo/ordine.
Tipi frontend: summary, table, timeline, terminal, text, commands, logs, json,
visualization, visualization_list, artifact_list. Tipi sconosciuti hanno un fallback
strutturato consultabile. Tutto viene inserito come testo, mai come HTML del plugin.

Per controllare gruppi, sezioni, sorgenti, etichette e formati aggiungere il blocco
`presentation` descritto in [Output mapping](../docs/OUTPUT_MAPPING.md). Il JSON
originale rimane in una vista tecnica secondaria, chiusa inizialmente.

Il motore SVG riconosce:

| Tipo | Dati |
| --- | --- |
| line, area, bar, scatter, coordinates, comparison | array di oggetti x/y; mapping `encoding.x.field` e `encoding.y.field` |
| histogram, distribution | array di valori oppure oggetti con campo x; binning automatico |
| pie, donut | array con label e y/value non negativo; colori e pattern accessibili |
| timeline | array con timestamp/start ISO e label/event |
| tree, graph, network_graph, execution_graph | oggetto `nodes` e `edges`, collegamenti source/target |
| heatmap, matrix | matrice annidata oppure celle x/y/value |
| byte_grid, hex_map | array di byte o celle x/y/value, etichette hex |
| offset_map | x = offset iniziale, y = lunghezza |
| diff | celle x/y/before/after; evidenzia differenze tramite riempimento/bordi |

Le descrizioni hanno title, type, data, encoding, options e palette. Il plugin
dichiara una palette registrata nel blocco `presentation` del proprio
`output_schema.json`, per esempio `"palette": "network"`; una singola
visualizzazione può dichiararne un'altra. Le palette ammesse sono `forensic`,
`document`, `filesystem`, `network`, `signal`, `archive`, `code`, `text` e
`monochrome`. Il core rifiuta nomi e colori arbitrari e restituisce anche i token
`background`, `surface`, `foreground`, `primary`, `secondary`, `critical` e
`muted`. Una sezione può scegliere il ruolo con `"tone": "secondary"` o
`"tone": "critical"`. Se manca type viene inferito bar o graph e segnalato come
inferito. Massimo 10.000 elementi. I renderer offrono selezione, filtro, tooltip,
zoom/pan ed export; la selezione emette `hub-select` e evidenzia la riga corrispondente
nella sezione. Per associazioni usare `artifact_id`/`node_id` nel JSON del grafico.
Il sincronismo avanzato fra grafici con assi diversi richiede che il plugin fornisca
chiavi/indici coerenti: l'engine non inventa corrispondenze tra dati diversi.

Le sezioni possono dichiarare `fields`/`columns` per l’ordine delle colonne, e
`actions: [{"type":"plugin_endpoint","label":"Dettagli","path":"/about","method":"GET"}]`.
Il frontend verifica che l’endpoint sia dichiarato nel manifest prima di invocarlo.

## Endpoint personalizzati

Dichiarare, ad esempio:

```json
{"endpoints":[{"path":"/about","method":"GET","handler":"about"}]}
```

Il loader registra `/api/plugins/ID/about`, senza importare un router nel processo
principale. Implementare `about(request_dict, context)` sulla classe del plugin o
in un modulo dichiarato da `custom_routes: "routes.py"`. In quest'ultimo caso la
funzione è esportata dal modulo. Anche l'handler viene eseguito in isolamento.
I path sono statici e relativi al namespace; duplicati e traversal sono rifiutati.
Non sono supportati router FastAPI arbitrari dentro il processo API: questo mantiene
il confine di isolamento anche per i plugin che espongono endpoint.

## Verificare un nuovo plugin

Aggiungere test per la logica specifica nella directory del plugin, eseguirli nel suo
ambiente e verificare la disponibilità via `/api/plugins`. Creare un caso di test,
caricare input rappresentativo ed eseguire il plugin dalla UI. Non inserire copie di
evidenze reali, segreti o directory personali nel pacchetto del plugin.

## Input ad accesso casuale e workspace

`input_access` vale `bounded` per default: il sandbox espone solo la vista
consentita dal budget. Un analizzatore di filesystem può dichiarare
`random_access`: soltanto durante `analyze` riceve il singolo file autorizzato
completo in sola lettura, entro `HUB_MAX_UPLOAD`. Non riceve altri asset o file
vicini. Deve applicare il proprio budget alle scansioni e riportare i limiti;
le letture interne di tool esterni non sono conteggiate dal core.

`workspace_bytes` separa spazio di lavoro e dimensione massima dei file temporanei
dal budget `output_bytes` per gli artefatti esportati. È limitato da
`HUB_MAX_WORKSPACE_BYTES` (1 GiB). Senza questa dichiarazione il workspace mantiene
il limite output precedente. Timeout, CPU, memoria e isolamento restano attivi.
