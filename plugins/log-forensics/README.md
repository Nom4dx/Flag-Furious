# Log Forensics

Plugin offline e read-only per riconoscere, normalizzare e correlare log singoli,
rotazioni, directory e contenitori compressi. Conserva file, riga, byte offset,
timestamp raw, parser e campi originali. L'interfaccia mostra una copia raw
mascherata; l'evidenza originale immutabile resta l'autorità forense.

## Pipeline e architettura

`format_detector.py` assegna score da struttura e schema; l'estensione vale solo
come indizio. `parser_registry.py` seleziona parser passivi. `normalizer.py`
produce eventi ECS-inspired senza eliminare campi sconosciuti. Timeline, entità,
sessioni, detection, Sigma, anomalie, correlazioni, attack chain, decoder e flag
sono fasi indipendenti. Grafici e grafi sono JSON interpretati dall'engine 2D.

Parser inclusi: testo/multilinea, RFC3164/5424, Apache Common/Combined, Nginx
access/error, IIS W3C, JSON/JSONL/NDJSON, CSV/TSV/pipe, logfmt, CEF, LEEF, GELF,
XML, Windows Event XML, Sysmon, EVTX tramite `python-evtx`, journald export,
auditd, Zeek TSV/JSON, Suricata EVE, firewall key/value, CloudTrail, Azure,
GCP Audit e Kubernetes Audit. Una riga JSON corrotta non annulla quelle valide.

## Detection e correlazione

Le regole integrate rilevano brute force, password spraying, successo dopo
fallimenti, SQL/command injection, XSS, traversal, percorsi sensibili,
PowerShell encoded, LOLBins, reverse shell, log clearing, cron persistence,
port scan, DNS tunneling, beacon periodico, cambi privilegi cloud e Kubernetes
exec. Brute force e scan richiedono soglie e raggruppamento; anomalie statistiche
rimangono `behavioral_anomaly`, non attacchi confermati.

Tre regole Sigma locali versionate coprono PowerShell codificato, cancellazione
dei Windows log e reverse shell Linux. Il valutatore interno supporta selection,
liste e modificatori contains/startswith/endswith. Regole Sigma più complesse e
correlation rules richiedono pySigma/Chainsaw/Hayabusa opzionali.

## Flag e payload

La ricerca usa prefissi e regex del caso. Cerca eventi singoli, Base64, hex, URL,
ROT13, gzip/zlib e concatenazioni ordinate per timestamp, riga, sequence,
sessione, request ID, flow ID e source IP. Ogni risultato riporta eventi,
sorgenti, strategia, decoder, evidenza e confidenza. I payload con firma o testo
significativo sono artefatti derivati e vengono reinseriti nella pipeline.

## Sicurezza e privacy

Nessun dato lascia la macchina. Non vengono fatti lookup, eseguiti log, script o
payload. ZIP traversal, symlink, archive bomb, output, righe, eventi, file,
decoder e byte sono limitati. Password, token, API key, cookie e authorization
sono mascherati nelle viste; i file originali non vengono modificati. I tool sono
allow-listed, `shell=False`, bounded e isolati dal core.
Anche gli asset inline testuali/JSON rispettano `byte_budget`: vengono codificati
a frammenti, la vista troncata è segnalata come `partial` e i byte non vengono
duplicati in una serializzazione completa prima del parsing.
Gli hash del core vengono riusati quando disponibili; altrimenti il calcolo locale
si ferma al byte budget e identifica esplicitamente hash/prefisso incompleto.

## Dipendenze e tool

Nessuna dipendenza obbligatoria oltre al Forensic Hub. Opzionali: `python-evtx`,
`PyYAML`, `pysigma`, `dissect`, `regipy`, `maxminddb`. Tool opzionali:
`journalctl`, Chainsaw, Hayabusa, EvtxECmd, jq, ripgrep, Zeek, Suricata e Logstash.
Assenza di un tool riduce soltanto la relativa fase.

## Estensione

Per un parser nuovo creare `src/parsers/<nome>.py` con `parse(data, source,
context)`, registrarlo in `parser_registry.MAPPING`, aggiungere prove content-first
in `format_detector` e fixture valide/corrotte. Per una detection aggiungere una
regola correlata in `detection_engine` oppure YAML locale sotto `rules/custom`.
Per una flag aggiungere prefisso/regex nelle opzioni del caso; per un decoder
aggiungere una trasformazione bounded in `decoder_pipeline._decoders`.

## Limiti

EVT legacy e journald binario richiedono parser/tool opzionali. Il sottoinsieme
Sigma interno non implementa l'intero linguaggio Sigma. GeoIP funziona soltanto
con database locale esplicitamente configurato. Baseline e impossible travel
accurati richiedono storico e geodati affidabili; non vengono inventati. NetFlow
binario e formati vendor proprietari richiedono adapter dedicati.
