# Beta test — forensics challenge pack

Data: 12 settembre 2026. Dataset: `forensics_challenges_verified`, 8 challenge.
I case sono stati creati nel framework con il nome della challenge e i prefissi
sono stati ricavati dal writeup prima dell'esecuzione (`BVAULT` oppure `SVIUSCG`).
Tutte le prove hanno usato l'API locale, modalità `deep`, budget 64 MiB e pipeline
ricorsiva attiva. I flag riportati qui sono presenti nei writeup forniti.

## Risultato tecnico della piattaforma

| Challenge / case | Esito | Risultato osservato | Diagnosi |
| --- | --- | --- | --- |
| `challenge-02-phantom-document` | PASS | `BVAULT{ph4n70m_m374d474_r3v34l3d}` rilevata a offset 2248 | Magic Wrapper + flag detector hanno letto il valore XMP; non è attribuito come finding semantico EXIF. |
| `challenge-06-schizophrenic-malware` | PASS con rumore | `BVAULT{dns_exf1l7r4710n_m4lw4r3_c4u9h7}` rilevata a offset 36848 | Pic-up analizza il PCAP e il detector trova il risultato. Il job è `partial` perché la scansione firme Magic ha raggiunto un limite, non perché la soluzione sia mancata. |
| `challenge-02-polyglot-paradox` | FAIL | Solo le due flag esca PDF/Python; flag reale non trovata | Archive Extractor estrae il ZIP e arriva a `secret.jpg`, ma non interpreta EXIF/commento come Brainfuck né valida una flag rispetto alle esche. Una seconda estrazione ricorsiva fallisce su una derivata ZIP con central directory non valida. |
| `challenge-03-chronos-anomaly` | FAIL | Nessuna flag | Pic-up registra traffico/stream, ma non applica una decodifica delta-temporale ICMP -> byte ASCII. |
| `challenge-06-infinite-void` | FAIL | Nessuna flag | Text Inspector riconosce testo ma non inventaria/decodifica U+200B/U+200C. |
| `broken-envelope` | FAIL | Nessuna flag | Magic Wrapper segnala incoerenza/danneggiamento; Archive Extractor non viene proposto per il ZIP non valido e non esiste una riparazione EOCD conservativa. |
| `cloudy-with-a-chance-of-breach` | NON VALUTABILE | Nessuna flag nei due log forniti | Il writeup richiede shell, AWS IMDS, credenziali e un bucket S3; questi asset non sono nel pacchetto e non dichiara un formato o valore flag. Text Inspector non correla i due log. |
| `oakhash` | FAIL | Nessuna flag | Text Inspector mostra il formato `$oak$...`; non esiste un plugin per riconoscere, verificare o cercare candidati per OakHash. |

Due challenge su otto producono la flag attesa direttamente. La metrica è utile
solo per questo pack: la challenge cloud non è valutabile con gli asset consegnati.

## Problemi della piattaforma e dei plugin esistenti

1. **Attribuzione dei finding.** PDF e DNS hanno avuto successo soprattutto grazie
   alla scansione raw globale. Il risultato non identifica con precisione il campo
   XMP o la catena DNS/Base64 che costituisce la prova. Serve che Magic Wrapper e
   Pic-up emettano finding strutturati con `source`, offset, decoder e confidenza.

2. **Matcher troppo larghi e ricorsione rumorosa.** Pic-up viene avviato su PDF,
   testo e derivati non PCAP; Githappens viene proposto su ZIP danneggiati. Nei job
   PCAP/PDF questo ha creato esecuzioni ripetute su artefatti derivati e falsi
   percorsi. I matcher devono richiedere magic PCAP/PCAPNG e Githappens deve
   richiedere firme Git/repository, non un generico `file`/`archive`.

3. **Gestione falsi positivi.** La pipeline mostra le flag esca del polyglot allo
   stesso livello della soluzione. Occorre un modello `candidate` con evidenza,
   trasformazioni e un ranking che preferisca una flag ottenuta da un decoder o da
   un artefatto interno rispetto a una stringa raw.

4. **Archivi danneggiati.** La rilevazione Magic è corretta ma non guida una fase
   di ricostruzione. La riparazione deve lavorare su una copia, mostrare le modifiche
   e produrre una validazione ZIP; non deve alterare l'evidenza.

5. **Correlazione multi-asset.** I log cloud sono analizzati singolarmente. Il core
   deve poter consegnare a un plugin un insieme ordinato di asset dello stesso caso,
   con timeline e campi estratti, senza ricorrere a un file concatenato implicito.

6. **Stato del job.** La scansione Magic parziale rende `partial` anche quando la
   flag e il plugin selezionato hanno completato. Distinguere `triage_partial` da
   `analysis_partial` nel riepilogo evita un esito fuorviante.

## Capacità sconosciute e plugin generali da creare

La priorità segue numero di casi coperti, riuso e dipendenze. Ogni plugin deve
ricevere input read-only, dichiarare limiti, produrre finding/artefatti/decoder
tracciabili e non eseguire script contenuti nell'evidenza.

### 1. `steg-decoder`

Copre: polyglot, zero-width e futuri casi di testo/immagine con dati nascosti.

Matcher: Unicode invisibile, EXIF/XMP/commenti, appendici di file, stringhe con
alfabeto di Brainfuck/Base64/hex/binary/morse. Pipeline: inventario di codepoint
e metadati, estrazione di stringhe candidate, decodifiche dichiarate in sequenza,
validazione formato flag e prova reversibile. Primo set: U+200B/U+200C bitstream,
Brainfuck, Base64, hex, URL encoding e ROT13. Output: tabella carattere/offset,
payload intermedio, catena decoder, flag con confidenza. Non deve assumere che una
stringa `BVAULT{...}` raw sia la risposta finale.

### 2. `pcap-covert-channel`

Copre: Chronos e future covert channel temporali/DNS/packet-length.

Matcher: PCAP/PCAPNG validi; usa i protocolli osservati come evidenza, non solo
l'estensione. Pipeline: timeline per flusso, delta inter-packet, clustering e
test di trasformazioni (millisecondi -> ASCII, bit timing, lunghezza -> byte),
con soglia configurabile e checksum/formato flag come validazione. Deve riusare
i JSON di Pic-up quando disponibili, ma poter analizzare un PCAP autonomamente.
Output: grafico delta, sequenza di byte, decoder scelto, errore di quantizzazione
e flag. Pic-up va prima corretto per non candidarsi fuori dal formato PCAP.

### 3. `archive-repair-and-extract`

Copre: Broken Envelope e ZIP/TAR/GZIP con header, central directory o EOCD
incompleti. Pipeline generale: identifica firme a offset, verifica record locali,
ricostruisce central directory/EOCD in una copia derivata, confronta hash prima e
dopo, valida con parser ZIP e poi estrae entro limiti anti-bomb. Espone sempre il
piano di patch; la riparazione richiede azione dell'utente. Integra decoder
testuali (Base64/hex) sugli artefatti estratti. Questo amplia `archive-extractor`,
ma conviene come plugin separato perché è mutazione di una copia e ha UX distinta.

### 4. `hash-format-analyzer`

Copre: OakHash e formati custom di challenge. Matcher: prefissi/grammatiche hash,
lunghezza digest e file di algoritmo allegati. Primo comportamento generale:
riconoscimento, parsing di versione/salt/costo, estrazione di hint (CRC, mask,
wordlist), verifica di un candidato mediante algoritmo dichiarato e ricerca
limitata su combinazioni/wordlist. Per OakHash implementare un adapter versione 1/2
con 65.536 round e checkpoint; non è corretto chiamarlo “cracking universale”.
Output: formato, costo stimato, strategia, candidati provati, prova hash e flag.

### 5. `log-correlation-and-cloud-trail`

Copre: Cloudy e casi con log ripartiti. Input: più asset testuali dello stesso
case, ordinati per timestamp. Pipeline: parser regolabili, normalizzazione eventi,
timeline multi-file, entity correlation (IP, utente, host, URL, AWS ARN/bucket),
regole IMDS/credential/cron/S3 e richieste di asset mancanti. Non deve contattare
AWS automaticamente: URL, credenziali e comandi sono solo evidenze/proposte.
Output: catena d'attacco, eventi anomali, richieste di dati mancanti e flag solo
se contenuta negli asset. Per questa challenge deve concludere esplicitamente
“evidenza insufficiente”, non “nessuna flag”.

## Ordine di implementazione consigliato

1. Correggere matcher, ranking flag e stato `partial` del core.
2. `steg-decoder` (risolve due gap e completa il polyglot dopo Archive Extractor).
3. `pcap-covert-channel` (riusa la base PCAP esistente).
4. `archive-repair-and-extract`.
5. `hash-format-analyzer` con OakHash come primo adapter.
6. `log-correlation-and-cloud-trail` e supporto multi-asset nel core.

## Tracciabilità dei test

| Case | Job |
| --- | --- |
| phantom document | `78547557c3184535a12330f25b25e551` |
| DNS malware | `a960949eb4d040b4b4b4fa811d411bf2` |
| polyglot | `3842a500b7b04e399992c30de63ed054` |
| Chronos | `b3b24de02c0a43d096a6848d4d786db5` |
| Infinite Void | `6ebf8a75a2454538b56d7fc4b0a4041f` |
| Broken Envelope | `e73595235da143df924585e312c9e74f` |
| Cloudy | `84dc2442943c4e44a445f6804615923d` |
| OakHash | `9d47631d861240e7bad427b03c133217` |
