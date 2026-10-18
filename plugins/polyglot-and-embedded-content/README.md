# Polyglot & Embedded Content

Plugin statico del Forensic Hub per distinguere una **firma trovata** da un
**formato strutturalmente validato**, calcolarne il confine logico e recuperare
contenuti concatenati o incorporati senza eseguirli.

## Architettura

`signatures.py` esegue una scansione streaming con sovrapposizione dei blocchi.
`boundary_detector.py` inoltra ogni possibile radice ai validator di
`validators.py`. Solo gli intervalli validati raggiungono classificazione,
carving e ranking ad alta confidenza. I marker secondari, come ZIP central
directory ed EOCD, restano nell'inventario e non diventano falsi archivi.

La pipeline è:

1. hash e copertura del byte budget;
2. inventario delle firme;
3. validazione strutturale e confini esclusivi `[start, end)`;
4. relazioni prefix, suffix, embedded, overlapping, concatenated e SFX;
5. analisi statica specifica di PDF, PNG, JPEG, script e archivi;
6. carving esatto e estrazione ZIP sicura;
7. decoder limitati e flag hunting con provenienza;
8. decoy ranking, mappa offset, grafo e report JSON.

Il plugin estende `app.core.plugin.BasePlugin`, non registra API parallele e usa
il normale artifact manager e la pipeline ricorsiva dell'hub. Ogni artefatto
derivato viene reinserito dal core; SHA-256 e limiti di profondità del job
impediscono cicli. Un report JSON è salvato nella directory di output isolata.

## Formati

I validator completi coprono ZIP, PNG, JPEG, PDF, GIF, RIFF/WAVE/WebP, GZIP,
BZip2, XZ, TAR, CPIO, 7z, PE, ELF, Mach-O, SQLite, Java class, WASM, OLE,
ISO9660, XML, HTML e script con shebang/PowerShell/batch. RAR viene validato in
modo conservativo fino al primo block header e dichiara che il confine non è
esatto. Le firme e i livelli di prova sono descritti in
[`docs/signatures.md`](docs/signatures.md) e gli algoritmi in
[`docs/algorithms.md`](docs/algorithms.md).

## Dipendenze

Non esistono dipendenze Python o binari obbligatori: i parser principali usano
la libreria standard. `7z` e `unrar` sono dichiarati opzionali per future
estensioni, ma la versione corrente non avvia subprocessi. Il plugin funziona
senza rete, root, mount o interpreti esterni.

## Output e dashboard

`output_schema.json` organizza la dashboard indipendente del plugin in Summary,
Signatures and validation, Polyglot and boundaries, Embedded content, Format
analysis, Decoys/payloads/flags e Artifact graph. I risultati validati vengono
prima; candidate respinte e utility diagnostiche restano in sezioni successive.
La mappa offset e il grafo usano JSON dell'engine 2D e la palette `archive`.
Il frontend generale conserva il pulsante “Torna ai casi”, la route del job e
lo scroll manuale dei log; il plugin non introduce codice UI o autoscroll.

## Sicurezza

L'originale è aperto solo in lettura. ZIP Slip, path assoluti, nomi drive,
symlink, rapporto di espansione, dimensione membro, totale estratto e numero di
entry sono controllati prima della scrittura. Le macro, gli script, gli SFX, le
azioni PDF, HTML e gli artefatti estratti non vengono mai eseguiti. I nomi sono
ridotti a basename sicuri e gli artefatti identici sono deduplicati con SHA-256.
Dettagli: [`docs/security.md`](docs/security.md).

## Esempio

Per un `PNG || ZIP` il risultato principale contiene due intervalli validati:

```json
{
  "format": "zip",
  "start_offset": 8241,
  "end_offset": 19281,
  "length": 11040,
  "boundary_method": "eocd_central_directory_and_crc",
  "validated": true,
  "confidence": 0.995
}
```

Il membro ZIP estratto conserva `source_offset`, `internal_path`,
`extraction_method`, SHA-256 e relazione al nodo formato. Le flag indicano
decoder, offset, contesto e catena completa.
La ricerca flag sugli artefatti derivati legge al massimo 16 MiB per artefatto;
se l'artefatto è più grande, il report espone la riduzione di copertura e passa a
`partial`.

## Test

Eseguire:

```text
.venv/bin/python -m pytest -q plugins/polyglot-and-embedded-content/tests
.venv/bin/python -m pytest -q tests/test_polyglot_plugin.py
```

Le fixture sono generate localmente e coprono PNG/PDF/script con ZIP, ZIP in
chunk custom, firma casuale, carving/deduplica, decoder, decoy, Zip Slip,
symlink e archive bomb. L'integrazione verifica loader, worker isolato,
presentazione, artefatti, grafo, flag e immutabilità.

## Estendere i parser

Inserire la firma in `SIGNATURES`, implementare un validator che restituisca un
confine esclusivo provato e registrare il nome nel record. Un nuovo analyzer può
arricchire soltanto formati già validati. Non usare mai il solo marker come prova
e non scrivere nella directory dell'asset. Aggiornare schema, documentazione e
fixture per includere un marker casuale che il validator deve respingere.

## Limiti conosciuti

ZIP cifrati vengono inventariati ma non estratti. RAR, 7z e OLE non hanno ancora
estrazione interna; RAR espone un confine conservativo. PDF xref stream complessi
sono accettati solo quando lo `startxref` punta a un oggetto plausibile; gli
stream con filtri complessi non vengono decodificati. Il rilevamento di polyglot
overlapping dipende dai parser disponibili e non prova equivalenza semantica tra
due interpretazioni. Questi limiti generano warning o confidenza ridotta, mai un
successo strutturale inventato.

