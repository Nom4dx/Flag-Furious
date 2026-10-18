# Presentazione degli output dei plugin

Il frontend usa un engine centrale JSON → componenti: dati scalari come valori
etichettati, oggetti come schede di proprietà, array di record come tabelle e
strutture annidate come dettagli espandibili. Il tema conserva il fondo nero e
usa accenti provenienti da palette validate centralmente. Il JSON originale resta disponibile in una vista tecnica chiusa.
Non serve scrivere JavaScript o HTML per un plugin.

## Mapping esplicito

Aggiungere `presentation` a `output_schema.json`, mantenendo le definizioni
`sections` del contratto di output. Esempio per un risultato con
`sections: [{"id": "analysis", "data": {"hosts": [...]}}]`:

```json
{
  "sections": [{"id": "analysis", "title": "Analisi", "type": "json"}],
  "presentation": {
    "version": 1,
    "palette": "network",
    "include_unmapped": true,
    "groups": [
      {"id": "network", "title": "Rete", "order": 1},
      {"id": "execution", "title": "Esecuzione", "order": 2}
    ],
    "sections": [
      {
        "id": "hosts",
        "title": "Host rilevati",
        "description": "Endpoint osservati nella cattura.",
        "source": "data.analysis.hosts",
        "group": "network",
        "type": "table",
        "order": 1,
        "hide_empty": true,
        "collapsed": false,
        "fields": [
          {"field": "address", "label": "Indirizzo", "format": "code"},
          {"field": "traffic.bytes", "label": "Traffico", "format": "bytes"},
          {"field": "confidence", "label": "Affidabilità", "format": "percent"}
        ]
      },
      {
        "id": "metrics",
        "title": "Metriche di esecuzione",
        "source": "metrics",
        "group": "execution",
        "type": "metrics",
        "fields": [
          {"field": "duration", "label": "Durata", "format": "duration"},
          {"field": "bytes_read", "label": "Byte analizzati", "format": "bytes"}
        ]
      }
    ]
  }
}
```

`source` parte dal risultato normalizzato. `data.<id>` accede ai dati di una
sezione originale. Sono ammessi chiavi separate da punti e indici di array
(`data.analysis.hosts.0.address`), senza espressioni, wildcard o codice eseguibile.
I percorsi di `fields` sono relativi al record della tabella o all'oggetto mostrato.

## Sezioni e formati

| Proprietà | Comportamento |
| --- | --- |
| `group` | ID di un gruppo dichiarato; genera la navigazione per sezioni |
| `order` | Ordine crescente di gruppi e sezioni |
| `type` | `auto`, `summary`, `metrics`, `details`, `table`, `list`, `text`, `terminal`, `timeline`, `visualization`, `visualization_list`, `artifact_list` |
| `fields` | Ordine, percorsi, etichette e formati dei valori/colonne |
| `hide_empty` | Nasconde null, stringhe vuote, array e oggetti vuoti; conserva zero e false |
| `collapsed` | Inizialmente chiude la sezione, apribile dall'utente |
| `include_unmapped` | Mostra i dati non mappati in «Altri dati»; predefinito true |
| `palette` | Palette registrata scelta dal plugin: `forensic`, `document`, `filesystem`, `network`, `signal`, `archive`, `code`, `text`, `monochrome` |
| `tone` | Ruolo cromatico della sezione: `primary`, `secondary`, `critical`, `muted` |

Formati: `auto`, `text`, `number`, `bytes` (unità binarie), `percent` (frazione
0–1), `duration` (secondi), `datetime` (data ISO), `hex`, `code`, `boolean`, `tags`.
`unit` aggiunge un suffisso; `description` descrive il campo. I valori originali
rimangono invariati. Le tabelle hanno ricerca anche nei campi non visualizzati,
pagine di 25 righe e apertura del record completo. Senza colonne esplicite vengono
mostrate le prime sei, con tutti gli altri campi accessibili nel dettaglio.

Grafici, timeline e artefatti mantengono il rispettivo contratto JSON. La palette
del mapping viene applicata ai grafici privi di una scelta esplicita e il backend
include i token risolti nel risultato, così il frontend non accetta CSS libero dal
plugin. Per i
grafici impostare `type: "visualization_list"` e una `source` contenente le
descrizioni per l'engine SVG. Le azioni `plugin_endpoint` restano limitate agli
endpoint dichiarati nel manifest.

## Compatibilità e validazione

Il loader valida ID, gruppi, tipi, formati e percorsi all'avvio; un mapping
malformato disabilita soltanto il relativo plugin. Riavviare il servizio dopo
aver modificato gli schemi. Il backend applica il mapping nelle risposte API dei
risultati e dei nodi del grafo: anche i casi già salvati ottengono la nuova
presentazione, senza rieseguire l'analisi o riscrivere le evidenze.

I plugin senza `presentation` usano il renderer strutturato automatico, anche
per le vecchie sezioni `type: "json"`. Nessun contenuto del plugin viene
interpretato come HTML. Il mapping è una descrizione della vista, non una
trasformazione dei dati forensic.
