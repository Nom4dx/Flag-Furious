# Review UI/UX del Forensic Hub

Data della review: 12 settembre 2026  
Prospettiva: utente esterno che conosce la digital forensics, ma non il codice o
il contratto interno dei plugin.

## Scopo e metodo

La review ha verificato questi percorsi:

1. orientamento nella schermata iniziale;
2. selezione o creazione di un caso;
3. acquisizione di file, testo e dati strutturati;
4. scelta dei plugin e avvio del job;
5. lettura di un job completato o parziale;
6. consultazione di risultati, flag, artefatti, log e grafo;
7. navigazione da tastiera;
8. utilizzo a 1440 × 900 e 390 × 844 pixel;
9. comportamento con 16 casi registrati;
10. comportamento con un caso reale contenente 21 asset, 45 risultati e un
    grafo di 314 nodi.

Sono stati usati Chromium headless, le API locali e casi già presenti. Non sono
stati modificati asset, job o risultati.

## Stato dell'implementazione

Le correzioni principali della review sono state applicate alla UI. La verifica
successiva sullo stesso caso da 21 asset ha misurato:

| Indicatore | Prima | Dopo |
| --- | ---: | ---: |
| Nodi DOM al primo caricamento | 23.772 | 644 |
| Markup serializzato iniziale | circa 6 MB | circa 58 KB |
| Nodi del grafo iniziale | 314 | 10 raggruppati |
| Risultati montati contemporaneamente | 45 aperti | una sezione e un asset alla volta |
| Altezza home desktop con 16 casi | 1.646 px | 900 px, pari alla viewport |
| Altezza rail casi desktop | 1.531 px | 785 px con scroll interno |
| Altezza navigazione analisi mobile chiusa | 337 px | 65 px |

Sono stati implementati anche riepilogo iniziale, dashboard indipendenti per
plugin, diagnostica in fondo, stato «Nessun riscontro» senza sezioni vuote,
provenienza e copia delle flag, ricerca casi, menu mobile richiudibili, permalink
di plugin/sezione, tab ARIA e navigazione con frecce.

Screenshot dopo la correzione:

- [Riepilogo del caso grande](../test-results/ux-fixed-summary-large.png)
- [Dashboard del plugin](../test-results/ux-fixed-plugin-dashboard.png)
- [Menu sezioni mobile](../test-results/ux-fixed-mobile-menu.png)
- [Plugin senza riscontri](../test-results/plugin-no-results.png)
- [Acquisizione desktop con rail indipendente](../test-results/ux-fixed-intake-desktop.png)

Restano interventi evolutivi non necessari al nuovo flusso: paginazione server
dei risultati, drawer mobile animato, dialog applicativo per l'eliminazione e
test manuale con screen reader.

Screenshot di riferimento:

- [Acquisizione desktop](../test-results/ux-audit-intake-desktop.png)
- [Analisi con caso grande](../test-results/ux-audit-analysis-large.png)
- [Risultati con caso grande](../test-results/ux-audit-results-large.png)
- [Flag candidate](../test-results/ux-audit-flags-large.png)
- [Acquisizione mobile](../test-results/ux-audit-intake-mobile.png)
- [Analisi mobile](../test-results/ux-audit-analysis-mobile.png)

## Valutazione esterna

L'identità visiva è coerente e riconoscibile. Il tema nero, la tipografia, le
linee e i pattern comunicano bene un ambiente tecnico. La separazione tra plugin
nella barra sinistra è più chiara della precedente lista orizzontale. La route di
analisi è ricaricabile, lo scroll non viene forzato alla fine del job e non sono
emersi errori JavaScript durante i percorsi provati.

Un utente nuovo, però, non arriva rapidamente alla risposta principale. Al
termine dell'analisi viene aperto il grafo, mentre le informazioni decisive sono
esito, problemi, flag, finding e artefatti. Nei casi grandi il grafo e la vista
«Tutti i risultati» superano la quantità di informazioni che l'interfaccia può
presentare in modo comprensibile. Lo stato `partial` non spiega subito cosa sia
incompleto e quanto questo incida sui risultati.

| Area | Valutazione | Motivo principale |
| --- | ---: | --- |
| Identità e coerenza visiva | 8/10 | Tema forte, coerente e privo di elementi decorativi inutili |
| Comprensione dell'esito | 5/10 | Manca un riepilogo iniziale con priorità e spiegazione dello stato |
| Ricerca delle informazioni | 6/10 | Le sezioni plugin aiutano, ma i casi e i risultati grandi non hanno ricerca o filtri adeguati |
| Efficienza sui casi grandi | 3/10 | Rendering completo di decine di risultati e grafo con centinaia di nodi |
| Accessibilità operativa | 5/10 | Buon contrasto principale e skip link; tab, target piccoli e testo tecnico richiedono correzioni |
| Esperienza mobile | 6/10 | Nessun overflow della pagina, ma navigazione e sezioni precedono troppo il contenuto |

## Evidenze misurate

| Scenario | Evidenza | Impatto |
| --- | --- | --- |
| Home con 16 casi | documento alto 1.646 px in viewport da 900 px; rail alto 1.531 px | la lista casi allunga anche il main e crea un'estesa area vuota |
| Tastiera dalla home | dopo 14 `Tab` il focus è ancora nella lista casi | chi non usa subito lo skip link deve attraversare tutti i casi prima del form |
| Caso con 21 asset | 45 blocchi `.output-plugin`, tutti creati e aperti | alto costo DOM e scansione visiva difficile |
| Caso con 21 asset | 23.772 nodi DOM e circa 6 MB di markup serializzato | rallentamenti probabili su workstation meno potenti o report più grandi |
| Grafo grande | 314 nodi | il fit globale riduce nodi ed etichette fino a renderli illeggibili |
| Barra di analisi | 25 azioni alte meno di 32 px; link report alti 13 px | interazione scomoda, soprattutto con touch o limitazioni motorie |
| Tab ARIA | 5 tab senza `aria-controls` e 5 pannelli senza `aria-labelledby` | relazione tra controllo e contenuto non comunicata alle tecnologie assistive |
| Home mobile | lista casi larga 2.360 px dentro uno spazio di 350 px | scorrimento orizzontale disponibile ma poco evidente |
| Analisi mobile | il contenuto inizia a 692 px; la sidebar occupa 337 px da chiusa | quasi tutta la prima viewport è navigazione; aprendo un plugin il ritardo aumenta |

## Problemi e interventi

Le priorità indicano l'ordine di correzione. `P0` blocca la comprensione o la
scalabilità di casi realistici; `P1` rallenta attività frequenti; `P2` migliora
chiarezza e rifinitura.

### P0 — Introdurre un vero riepilogo dell'analisi

**Problema.** Il grafo è la vista iniziale. Lo stato `partial` è mostrato come
etichetta isolata e la motivazione è cercabile soltanto nei plugin o nei log.

**Correzione.** Aggiungere `Riepilogo` come prima voce e vista predefinita. Deve
mostrare, nell'ordine:

1. esito del job e una spiegazione in linguaggio naturale;
2. flag confermate o candidate più affidabili;
3. errori e warning che cambiano l'interpretazione dell'esito;
4. finding ordinati per severità e confidenza;
5. plugin che richiedono attenzione;
6. quantità di asset originali e derivati;
7. azioni successive disponibili.

Per uno stato parziale usare un testo come: «Analisi completata con risultati;
il modulo X non ha terminato per byte budget. Le flag trovate restano
consultabili». Separare visivamente `analysis_partial`, `triage_partial` e
`plugin_partial` quando il backend dispone di questa informazione.

**Criteri di accettazione.** Entro la prima viewport l'utente deve poter dire se
il job ha prodotto risultati, se esistono flag e perché lo stato non è completo,
senza aprire il grafo o i log.

### P0 — Rendere progressivo il rendering dei risultati

**Problema.** `renderOutputs` costruisce subito tutti i 45 risultati e imposta
ogni `<details>` come aperto. La barra aggrega correttamente i plugin, ma il DOM
continua a essere organizzato per coppia plugin/asset.

**Correzione.** Mantenere nel client un indice leggero:

```text
plugin
└── sezione
    └── asset
        └── risultato
```

Montare soltanto il plugin e la sezione selezionati. Per gli asset usare una
lista compatta con ricerca, stato e paginazione o virtualizzazione. Caricare il
dettaglio quando l'utente apre una riga. Il JSON tecnico deve essere creato solo
quando viene aperto. Conservare nel DOM al massimo il pannello corrente e una
piccola cache dei pannelli recenti.

Valutare un endpoint indicizzato come:

```text
GET /api/jobs/{job_id}/results/summary
GET /api/jobs/{job_id}/results?plugin_id=...&section_id=...&cursor=...
```

**Criteri di accettazione.** Sul caso di riferimento da 21 asset:

- meno di 5.000 nodi DOM al primo caricamento;
- nessun risultato espanso automaticamente in «Tutti i risultati»;
- cambio plugin o sezione percepito entro 100 ms dopo il caricamento dei dati;
- posizione, plugin e sezione preservati dopo polling e refresh;
- ricerca per nome asset, tipo, stato e testo del finding.

### P0 — Ridurre e rendere leggibile il grafo

**Problema.** 314 nodi vengono inseriti nella stessa superficie. Il fit globale
li riduce fino a trasformare il grafo in una trama senza etichette leggibili.

**Correzione.** Mostrare inizialmente un grafo collassato:

```text
Asset originali → Identificazione → Plugin → Asset derivati → Flag/Report
```

Raggruppare asset derivati equivalenti e fasi ripetute. Lasciare disattivate le
fasi interne per impostazione iniziale. Espandere un plugin o un asset su azione
esplicita, con limite di nodi visibili e breadcrumb del focus. Aggiungere:

- «Adatta alla selezione»;
- ricerca nodo;
- minimappa o indicatore della posizione;
- conteggio dei nodi nascosti nel gruppo;
- modalità elenco accessibile equivalente al grafo.

**Criteri di accettazione.** Il primo livello non deve superare 40–50 nodi. Nome,
stato e relazione di ogni nodo visibile devono essere leggibili senza zoom
manuale. L'espansione deve preservare il focus corrente.

### P1 — Correggere il registro dei casi

**Problema.** La rail cresce con tutti i casi, allunga il documento e porta il
footer molto sotto il contenuto utile. I nomi automatici `Analisi 12/09/2026`
generano duplicati. Non esistono ricerca, ordinamento o raggruppamento.

**Correzione.** Rendere la rail alta quanto la viewport, con scroll interno.
Aggiungere ricerca, ordinamento per ultimo aggiornamento e raggruppamento
facoltativo per stato. Generare nomi automatici distinguibili, per esempio nome
del primo asset oppure data e ora. Mostrare l'ultimo stato del caso senza aprirlo.

Su mobile sostituire il carosello orizzontale con un pulsante `Casi (16)` che
apre un drawer o dialog ricercabile. In questo modo il form inizia subito dopo
l'intestazione.

**Criteri di accettazione.** Aggiungere 100 casi non deve modificare l'altezza del
main. Un caso deve essere raggiungibile con ricerca e tastiera in meno di tre
azioni. Il mobile non deve richiedere uno swipe non segnalato.

### P1 — Dare priorità ai risultati nella barra laterale

**Problema.** La struttura per plugin è corretta, ma `Grafo esecuzione` occupa la
prima posizione. Report, errori e warning sono separati o poco visibili. Su
mobile la sidebar completa precede il contenuto.

**Correzione.** Ordinare le viste globali così:

1. Riepilogo;
2. Flag;
3. Problemi;
4. Plugin e sezioni;
5. Artefatti;
6. Timeline;
7. Grafo;
8. Log;
9. Report.

Su mobile mostrare una barra compatta e persistente con esito, flag e pulsante
`Sezioni`. Le sezioni vanno aperte in un drawer; la selezione chiude il drawer e
porta direttamente al contenuto.

### P1 — Migliorare la pagina delle flag

**Problema.** La flag è leggibile, ma `raw`, offset e asset non spiegano da soli
la qualità del risultato. Non è presente un'azione di copia chiaramente visibile.

**Correzione.** Ogni flag deve mostrare:

- classificazione (`confirmed`, `high confidence`, `candidate`, `suspicious`);
- confidenza numerica;
- plugin o detector responsabile;
- asset e percorso interno leggibili;
- offset e catena dei decoder;
- pulsante `Copia` con conferma non invasiva;
- azione `Apri origine`;
- eventuale relazione con finding o artefatto.

Le flag duplicate devono essere raggruppate mostrando tutte le provenienze.

### P1 — Rendere chiari acquisizione e avanzamento

**Problema.** `Modalità`, `Profondità`, hash atteso e compatibilità richiedono
conoscenza del framework. Durante upload e identificazione il pulsante viene
disabilitato, ma il testo non descrive la fase. Gli errori vengono mostrati nel
notice in cima al main, lontano dal controllo su mobile. La compatibilità usa il
punteggio, ma non chiarisce bene plugin per asset quando gli asset sono più di
uno.

**Correzione.** Aggiungere brevi spiegazioni contestuali e una stima dei limiti.
Durante l'acquisizione mostrare fase, file corrente, byte trasferiti e possibilità
di annullare. Portare l'errore vicino al campo coinvolto e spostare il focus sul
messaggio. Nella selezione plugin raggruppare per asset o mostrare esplicitamente
`compatibile con N asset`, con dettaglio apribile delle motivazioni.

Il riepilogo prima dell'avvio deve indicare: asset selezionati, plugin selezionati,
ricorsione, profondità e prefissi flag.

### P1 — Completare l'accessibilità dei componenti interattivi

**Problema.** I controlli con `role="tab"` non dichiarano il pannello controllato
e non implementano la navigazione con frecce. I link del report misurano solo 13
px di altezza. Numerosi testi tecnici usano 8–10 px. Il focus deve attraversare
tutti i casi se l'utente non attiva subito lo skip link.

**Correzione.** Applicare il pattern ARIA tabs completo:

- `id`, `aria-controls` e `aria-labelledby` collegati;
- un solo tab con `tabindex="0"`;
- frecce destra/sinistra o su/giù, Home ed End;
- focus trasferito al titolo del pannello quando richiesto dall'azione.

Portare i target primari ad almeno 36 px di altezza e quelli touch a 44 px. I
link report devono diventare pulsanti nominati `Scarica report JSON` e `Apri
report HTML`. Usare almeno 12 px per metadati persistenti e verificare il
contrasto del testo con opacità inferiore a 0,55. Rendere la lista casi un'unica
fermata nel percorso tastiera, con navigazione interna o ricerca.

### P2 — Conservare la posizione funzionale nel permalink

**Problema.** Il refresh conserva caso e job, ma riapre la vista predefinita. Non
conserva plugin, sezione, asset, filtri del grafo o riga selezionata.

**Correzione.** Serializzare lo stato utile nella query o nell'hash:

```text
/cases/{case_id}/analysis/{job_id}?view=plugin&plugin=pic-up&section=streams&asset=...
```

Aggiornare la URL con `replaceState` per i cambi frequenti e `pushState` per i
cambi di vista. Il link deve essere condivisibile e ripristinare soltanto lo
stato di navigazione, senza duplicare il job.

### P2 — Migliorare report e azioni distruttive

**Problema.** `JSON ↓` e `Report ↓` sono ambigui e piccoli. L'eliminazione usa il
dialog nativo del browser, visivamente estraneo all'applicazione.

**Correzione.** Spostare il report in una sezione con data di generazione,
formato, dimensione e azioni esplicite. Usare un dialog applicativo per eliminare
il caso, indicando quanti asset, artefatti e report verranno rimossi. Richiedere
la digitazione del nome soltanto per casi con dati consistenti.

## Architettura informativa proposta

```text
Caso / Job / Analisi
├── stato, avanzamento e azioni
├── Riepilogo
│   ├── Esito e copertura
│   ├── Flag principali
│   ├── Problemi da verificare
│   └── Finding prioritari
├── Plugin
│   └── Plugin selezionato
│       ├── Sezione
│       └── Asset / risultato
├── Flag
├── Artefatti
├── Timeline
├── Grafo
├── Log
└── Report
```

Il livello `asset / risultato` deve apparire solo quando serve. Il nome del caso,
lo stato e la navigazione principale restano visibili; dati tecnici, JSON raw e
log completi rimangono progressive disclosure.

## Piano di implementazione

### Iterazione 1 — Comprensione e scalabilità

File principali:

- `frontend/index.html`: nuova vista Riepilogo;
- `frontend/js/app.js`: indice plugin/sezione/asset, selezione e lazy rendering;
- `frontend/js/presentation.js`: creazione differita di tabelle, fold e JSON;
- `frontend/js/visualizations.js`: gruppi collassati ed espansione del grafo;
- `app/api/routes.py`: riepilogo e paginazione dei risultati, se necessari;
- `frontend/css/hub.css`: layout del riepilogo e stati strutturali.

Test obbligatori:

- caso con almeno 20 asset, 50 risultati e 300 nodi;
- DOM iniziale entro il budget;
- grafo iniziale sotto il limite di nodi;
- spiegazione dello stato parziale;
- apertura plugin/sezione/asset senza perdita dello scroll;
- refresh della route profonda.

### Iterazione 2 — Casi, mobile e acquisizione

Implementare rail con scroll interno e ricerca, drawer mobile, nomi automatici
univoci, feedback di upload e riepilogo pre-avvio. Verificare 0, 1, 20 e 100 casi,
file singolo, directory, più asset e fallimenti di upload.

### Iterazione 3 — Accessibilità e rifinitura

Completare tab ARIA, tastiera, dimensioni dei target, focus degli errori, azioni
flag/report e dialog distruttivi. Eseguire test con sola tastiera, zoom al 200%,
viewport da 320 px, `prefers-reduced-motion` e uno screen reader.

## Definition of done

La revisione può considerarsi risolta quando:

- il riepilogo è la prima vista e spiega sempre l'esito;
- un caso grande non monta tutti i risultati contemporaneamente;
- il grafo resta leggibile tramite raggruppamento ed espansione;
- la lista casi non modifica l'altezza del main;
- mobile apre il contenuto utile nella prima viewport;
- flag e problemi mostrano provenienza e azioni;
- plugin, sezione e asset selezionati sono condivisibili tramite URL;
- tabs, focus e target interattivi superano i test di accessibilità;
- i test esistenti su polling, scroll, grafo, artefatti e separazione dei plugin
  continuano a passare.

## Aspetti già validi da conservare

- palette nera e bianca coerente;
- distinzione dei plugin nella barra laterale;
- output mapping JSON verso componenti leggibili;
- JSON tecnico chiuso per impostazione iniziale;
- route del job ricaricabile;
- nessun autoscroll forzato sui risultati;
- log con follow esplicito;
- grafo utilizzabile da tastiera a livello del singolo nodo;
- assenza di overflow orizzontale globale nelle viewport provate;
- messaggi e output inseriti con `textContent`, senza HTML prodotto dai plugin.
