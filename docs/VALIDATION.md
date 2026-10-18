# Verifica della consegna

Eseguita l'11 settembre 2026 nell'ambiente Linux locale, Python 3.13.11,
FastAPI 0.118, Pydantic 2.12.4, bubblewrap e Chromium disponibili.

## Risultati

| Verifica | Esito |
| --- | --- |
| Suite framework (`.venv/bin/python -m pytest`) | **33 passati** |
| Magic Wrapper originale | **5 passati** |
| HIDGrabber originale | **15 passati** |
| pic-up originale | **19 passati** |
| Ext4atto originale | **33 passati** |
| GitHappens originale | **15 passati** |
| Totale test Python | **120 passati** |
| Ruff, core / adapter / test / script nuovi | **PASS** |
| Compilazione Python e controllo sintassi JavaScript | **PASS** |
| Integrità sorgenti importati | **76 SHA-256 invariati** |
| Browser desktop 1440×1100 e mobile 390×844 | **PASS** |
| 21 tipi di visualizzazione SVG | **PASS**, nessuna coordinata NaN |
| Palette computata su elementi visibili | **PASS**, nessun colore cromatico |
| Health, riferimento API e OpenAPI | **PASS** |
| Avvio finale senza privilegi elevati | **PASS**, processo eseguito come `nomad` |

## Copertura effettiva

La suite del framework verifica:

- avvio senza plugin e fallback per file;
- caricamento dei sei plugin, endpoint di esempio e fallimenti di import isolati;
- dipendenze, cicli, streaming e checkpoint parziali;
- hash multipli confrontati con hashlib, strutture PNG e CRC, falsa estensione;
- rilevamento di header danneggiato, rifiuto di riparazioni non validate,
  conferma esplicita, copia validata e immutabilità dell'originale;
- firme multiple/embedded e firme aggiuntive con wildcard e offset;
- asset testo, JSON, hex, URL testuali, directory e tipi futuri;
- estrazione ZIP e analisi ricorsiva, parent ID, hash, artefatti, download e anteprima;
- esecuzione di più plugin sullo stesso asset e chiamate reali ai quattro tool preservati;
- nodi/collegamenti, dipendenze, fasi, log e registrazione dei comandi CLI;
- ricerca flag raw, Base64, hex, URL, ROT13, inverso e split, oltre a timeout regex;
- timeout e annullamento dei job, limiti di memoria/file e budget parziali;
- blocco scrittura input, blocco rete e assenza del filesystem host nel worker;
- path traversal, symlink nei plugin, isolamento dei casi, origin e budget invalidi;
- persistenza dopo riavvio e marcatura dei job interrotti;
- normalizzazione/ordine delle sezioni, validazione dei tipi di grafico e report;
- eliminazione del caso e dei suoi asset, rifiutata durante un job attivo.

Il test browser acquisisce JSON dalla UI, esegue Text Inspector, seleziona nodi,
verifica lo zoom, consulta la flag e il grafico, prova tutti i renderer e controlla
l'assenza di overflow orizzontale sul mobile. Cancella il caso al termine.

Screenshot generati da `scripts/browser_smoke.py`:

- `test-results/desktop-intake.png`
- `test-results/desktop-results.png`
- `test-results/mobile.png`

## Limiti della verifica

I test non attestano l'analisi esaustiva di qualsiasi formato o immagine disco di
qualsiasi dimensione. Sono stati usati fixture sintetici, PCAP vuoto valido, piccola
immagine raw, ZIP e la suite originale dei tool. Le capacità opzionali dipendono dalle
CLI installate; non è stata eseguita una campagna di fuzzing o una verifica di evasione
del kernel. I limiti CPU/memoria sono per processo, non quote cgroup aggregate.

Il byte budget limita la vista di input e la sua allocazione nel job. I contatori
specifici degli analizzatori sono riportati separatamente. Le funzioni di scansione
di file cancellati, slack space, journal, Git, database e immagini richiedono che i
tool appropriati producano i dati. Gli URL rimangono testo e i plugin con rete/root
richiesti vengono rifiutati dalla policy locale.

La UI non è un servizio multiutente esposto pubblicamente. Il README descrive avvio,
configurazione, limiti e contratto di estensione senza modifiche del core.
