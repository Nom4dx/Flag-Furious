# Document Metadata Forensics

Plugin statico e isolato per trattare un documento come file, contenitore,
struttura binaria, oggetto visuale, archivio e sorgente di metadata/payload.
Non esegue macro, JavaScript PDF, DDE, formule, file embedded, HTML o comandi.

## Architettura

`entrypoint.py` espone `Plugin`; `plugin.py` orchestra moduli indipendenti in
`src/`. Ogni modulo restituisce `ModuleResult`, registra fase/durata e può
diventare `partial` senza fermare gli altri. `ArtifactStore` scrive soltanto in
`/work/document-metadata-forensics`, deduplica SHA-256 e usa nomi sicuri. Il core
trasferisce poi gli artefatti nella directory del caso e assegna gli ID finali.

Moduli: identification, metadata, EXIF, XMP, IPTC, PDF structure/revisions/
objects/layers, OOXML/ODF/EPUB, OLE, RTF, images, structured text, hidden content,
payload decoder, timeline, inconsistencies, flag hunter e reporting.

## Formati e capacità

PDF/PDF-A; JPEG/TIFF/PNG/WebP/HEIC/AVIF/GIF/SVG; DOCX/DOTX/DOCM, XLSX/XLSM,
PPTX/PPTM; DOC/XLS/PPT/OLE; RTF; ODT/ODS/ODP; EPUB; HTML/MHTML/XML/JSON; ZIP
documentali. Vengono analizzati proprietà standard/custom, EXIF/XMP/IPTC,
commenti, revisioni, fogli/slide nascosti, macro statiche, embedded objects,
stream PDF Flate, layer/OCG, rendering invisibile, dati dopo EOF, zero-width e
payload Base64/hex/Brainfuck.

Il decoder dei payload esamina al massimo 2.000 candidati, conserva fino a 1.000
risultati e 16 MiB cumulativi di dati decodificati (4 MiB per elemento); se
raggiunge un limite, il modulo segnala coverage parziale.
I controlli di testo invisibile e whitespace leggono al massimo 8 MiB; il modulo
segnala `partial` oltre quel limite e riporta i byte esaminati. La ricerca di
firme incorporate continua sull'intero buffer concesso.

Il supporto HEIC/AVIF/WebP/GIF consiste nell'inventario statico del contenitore e
nelle firme/metadata accessibili; non comprende un decoder completo di tutti i
box o extension block. Vedere [formati](docs/formats.md) e
[limiti](docs/limitations.md).

## Dipendenze

Dipendenze Python obbligatorie: nessuna oltre al runtime dell'hub. `olefile`, se
presente nell'ambiente, abilita stream e property set OLE; il fallback conserva
identificazione e warning. Binari obbligatori: nessuno. Opzionali dichiarati:
`exiftool`, `pdfinfo`, `pdftotext`, `olevba`; la versione 1.0 non li invoca e usa
parser Python interni, mantenendoli dichiarati per futuri arricchimenti verificati.

Il plugin usa bubblewrap, nessuna rete/root, timeout 180 s, CPU 150 s, memoria
1 GiB, vista input 128 MiB, workspace 256 MiB e output 64 MiB. Il limite finale
effettivo è sempre il più restrittivo tra manifest, job e server.

## Output e artefatti

Il risultato segue `Result` del core. Le sezioni hanno ID stabile, ordine, stato,
items, finding, artefatti, flag, timeline e visualizzazione. Il blocco
`presentation` di `output_schema.json` genera gruppi distinti nella UI. Le flag
sono `candidate` o `high_confidence`, con origine, percorso interno, parser,
decoder, offset e relazione. Vedere [output](docs/output.md).

Categorie logiche: `raw/`, `metadata/`, `pdf/`, `office/`, `ole/`, `rtf/`,
`images/`, `payloads/`, `timeline/`, `flags/`, più `metadata/report.json`.
L'Artifact Manager dell'hub conserva fisicamente i derivati per caso.

## Esempio

Caricare un PDF, impostare il prefisso corretto e selezionare il plugin. Per una
verifica diretta tramite API usare il normale flusso `/api/assets` e `/api/jobs`.
Non invocare l'entrypoint fuori dal worker: i percorsi e i budget sono forniti dal
core.

## Test e fixture

`python -m pytest plugins/document-metadata-forensics/tests -q` verifica firme,
metadata, PDF, Office, OLE fallback, RTF/zero-width, decoder e timeline. Le fixture
sono generate in memoria e non contengono documenti attivi. Il test integrativo
dell'hub verifica loader, sandbox, artefatti, flag e immutabilità. Il browser smoke
verifica route, navigazione, refresh, separazione dei plugin e scroll.

Per aggiungere un parser: creare un modulo con docstring e una funzione pubblica
che restituisce `ModuleResult`; imporre limiti prima di decomprimere/iterare;
preservare offset e percorso interno; aggiungere il modulo alla lista `phases` in
`Plugin.analyze`, lo schema UI e una fixture. Non importare librerie che eseguano
rendering attivo o risolvano URL.

## Decisioni e problemi noti

I parser interni privilegiano provenienza e comportamento deterministico rispetto
alla copertura di suite documentali complete. Gli indicatori visuali PDF sono
euristiche e restano `suspicious`. Un flag raw non viene promosso a confermato.
Il file funzionale richiesto come `Pasted markdown(2).md` non era disponibile nel
workspace/allegati durante questa implementazione; questa versione applica tutte
le specifiche incluse nel prompt. Confrontare quel documento quando disponibile.

Ulteriori dettagli: [sicurezza](docs/security.md), [casi di test](docs/test-cases.md).
