# pic-up

`pic-up` è un frontend automatico ed evidence-oriented per TShark, dedicato a
PCAP, PCAPNG, log e file generici in CTF e analisi forensi autorizzate. Combina
inventari di rete, ricostruzione TCP/UDP, timeline, Wireshark Expert Info, IOC,
credenziali in chiaro redatte, ricerca multilivello, carving, OCR, TLS key log e
controlli sui canali covert.

## Requisiti

- Python 3.11 o successivo;
- TShark per PCAP/PCAPNG;
- capinfos per metadati estesi e commenti globali, opzionale;
- Tesseract per l’OCR automatico, opzionale;
- editcap per `--embed-secrets`;
- text2pcap per il test di integrazione opzionale.

```bash
tshark --version
capinfos --version
tesseract --version
python3 pic-up.py --version
```

Il progetto non richiede dipendenze Python runtime. Può anche essere installato
come comando o eseguito come modulo:

```bash
python3 -m pip install .
pic-up capture.pcapng --all
python3 -m picup capture.pcapng
```

## Avvio rapido

```bash
python3 pic-up.py capture.pcapng
python3 pic-up.py capture.pcapng -f flag
python3 pic-up.py events.log -f CTF
```

Il report include SHA-256, protocolli, host, conversazioni, DNS, HTTP, TLS, hostname, commenti PCAPNG, flag, pattern, anomalie e candidati covert.

## Triage universale e portabilità

```bash
python3 pic-up.py capture.pcapng --all
python3 pic-up.py capture.pcapng --timeline both --timeline-limit 20000
python3 pic-up.py capture.pcapng --json > report.json
```

La modalità `--all` abilita ogni azione autonoma, esporta gli oggetti di
protocollo e produce `timeline.jsonl` e `timeline.csv`. Il report contiene:

- pseudo-sessioni UDP con confini dei datagrammi, direzioni e anteprime;
- timeline normalizzata UTC con frame, endpoint, porte, stack e Info;
- eventi Wireshark Expert Info;
- dettagli ARP, ICMP/ICMPv6, DHCP, NTP, SMB2, Kerberos e SSH;
- IOC deduplicati (IP, domini, URL ed email) con frame e first/last seen;
- materiale di autenticazione HTTP, FTP, SMTP, POP3, IMAP, IRC e Telnet.

Le credenziali sono sempre redatte e sostituite da lunghezza e SHA-256. Solo
`--show-secrets` ne mostra il valore, opzione da usare esclusivamente in un
ambiente controllato. Prima di interrogare i dissector, il runner scopre i campi
supportati dalla versione locale di TShark: campi opzionali come JA4 non rendono
più inutilizzabile l'intera analisi sulle versioni che non li espongono.

## Architettura

- `pic-up.py`: orchestrazione compatibile con la CLI storica, reporting,
  decodifica, carving e crittografia;
- `picup/network.py`: analizzatori di rete riutilizzabili, indipendenti dalla UI
  e testabili tramite una piccola interfaccia `fields`;
- `picup/__main__.py`: entry point per `python -m picup` e installazione;
- `test_pic_up.py`: unit test crypto, reassembly, CLI e inventari;
- `tests/fixtures`: fixture deterministiche per integrazione TShark.

## Transcript TCP e recupero XOR

Ogni cattura mostra ora i flussi TCP applicativi per direzione, con endpoint,
frame coinvolti, byte ricomposti e anteprima sia testuale sia esadecimale. Le
ritrasmissioni e gli overlap vengono deduplicati usando i sequence number.

Il tool cerca inoltre scambi challenge/response di uguale lunghezza in direzioni
opposte. Una chiave XOR viene segnalata **solo** se, applicata a un altro payload
dello stesso stream, produce testo plausibile o una flag. Chiave, frame usati e
frame decifrato rimangono nel report per rendere il risultato verificabile.

Il caso del writeup “Super Secret Agent 0x42” non richiede opzioni speciali:

```bash
python3 pic-up.py intercepted.pcap -f flag
```

Il risultato atteso nella sezione `Repeating-XOR recovery` è la chiave
`1c4ece63519493eb`; il plaintext decifrato entra anche nella normale ricerca CTF.

Per una chiave già nota:

```bash
python3 pic-up.py capture.pcap --xor-key hex:1c4ece63519493eb -f flag
python3 pic-up.py evidence.bin --xor-key base64:HE7OY1GUk+s=
```

Le forme accettate sono testo, `hex:...` e `base64:...`.
La chiave viene provata sia sui singoli payload (reset per messaggio) sia sui
byte ricomposti di ogni direzione (keystream continuo).

## Estrazione immagini e OCR

```bash
python3 pic-up.py capture.pcapng \
  --extract-images extracted-images \
  --flag-prefix flag
```

Il tool cerca PNG, JPEG, GIF, BMP e WebP in:

- payload e stream TCP/UDP;
- campi ricomposti HTTP, HTTP/2 e multipart;
- oggetti esportati con `--export-dir`;
- contenuti Base64, hex, URL encoded o compressi;
- file `.log`, comprese le data URI.

Ogni immagine riceve percorso, tipo MIME, dimensioni quando disponibili, SHA-256 e sorgente. Se Tesseract è installato, l’OCR parte automaticamente e il testo riconosciuto viene cercato nuovamente per flag e regex.

```bash
python3 pic-up.py capture.pcapng --extract-images images --no-ocr
```

Il carving non apre né esegue i file. `--force` consente una cartella già popolata senza modificare il file sorgente.

## Analisi dei `.log`

```bash
python3 pic-up.py application.log \
  -p 'password\s*[:=]\s*\S+' \
  --extract-images log-images
```

Vengono inventariati righe, IP, domini, URL, livelli e formato probabile. La ricerca comprende testo, Base64, Base32, hex, sequenze `0xNN`, URL encoding e zlib/gzip, con decodifica ricorsiva fino a tre livelli.

I valori dei segreti TLS non sono stampati nell’inventario: vengono riportati soltanto tipo e numero delle righe valide o malformate.

## TLS key log come input

Se l’input è `keys.log`, si può passare la cattura associata:

```bash
python3 pic-up.py keys.log \
  --capture capture.pcapng \
  --flag-prefix flag
```

Le righe `CLIENT_RANDOM`, `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0` e gli altri label noti vengono riconosciute automaticamente. Il key log viene applicato a TShark e l’inventario viene rigenerato dopo la decifratura, incluso HTTP/2 quando disponibile.

Resta valida anche la forma classica:

```bash
python3 pic-up.py capture.pcapng --tls-keylog keys.log
```

Per incorporare i segreti in una copia:

```bash
python3 pic-up.py capture.pcapng \
  --tls-keylog keys.log \
  --embed-secrets capture-with-secrets.pcapng
```

La copia è sensibile quanto il key log. Non pubblicarla e non sostituire l’evidenza originale.

## Ricostruzione e ricerca CTF

```bash
python3 pic-up.py capture.pcapng -f picoCTF
python3 pic-up.py capture.pcapng -p 'secret' -p 'token=[A-Za-z0-9]+'
```

Per TCP vengono confrontati:

- sequence number, eliminando sovrapposizioni e ritrasmissioni;
- ordine dei frame;
- ordine dei timestamp, utile nelle catture manipolate.

Per UDP vengono provati ordine dei frame e ordine temporale. Sono inoltre analizzati `tcp.reassembled.data`, `http.file_data`, `http2.data.data`, multipart, DNS frammentato e oggetti esportati. Sorgente ed encoding di ogni match permettono di verificare i duplicati.

## Commenti PCAPNG e canali covert

Il tool esamina:

- commento globale e commenti dei pacchetti;
- EtherType rari o `0xffff` e primo ottetto del MAC destinazione;
- sequenze con un byte per pacchetto TCP/UDP in ordine frame e timestamp;
- sequenze leggibili nei byte bassi di IP ID, porte, lunghezza frame e flag TCP.

I risultati appaiono in `PCAPNG comments` e `Covert-channel candidates`. Sono ipotesi riproducibili, non classificazioni certe.

## Filtri e catture derivate

```bash
python3 pic-up.py capture.pcapng --filter 'ip.addr == 10.10.10.5 && dns'
python3 pic-up.py capture.pcapng \
  --filter 'tcp.stream == 7' \
  --write-filtered stream-7.pcapng
```

Quando è attivo un filtro, la scansione grezza dell’intera cattura viene disabilitata affinché i match rispettino il filtro. Il sorgente non viene modificato.

## Esportazione oggetti

```bash
python3 pic-up.py capture.pcapng \
  --export-dir artifacts \
  --extract-images images
```

Vengono tentati HTTP, FTP-DATA, SMB, TFTP e IMF. Ogni artefatto riceve dimensione, tipo e SHA-256 ed entra nella ricerca e nel carving immagini.

## RC4 e RSA legacy

```bash
python3 pic-up.py capture.pcap --rc4-key 'known-key' -f CTF
python3 pic-up.py capture.pcap --rc4-key 'hex:001122aabbcc' --rc4-drop 256
python3 pic-up.py capture.pcap --rc4-key 'base64:c2VjcmV0'
```

RC4 viene tentato separatamente sui candidati. Protocolli proprietari possono richiedere framing, IV o reset diversi.

```bash
python3 pic-up.py capture.pcap \
  --tls-rsa-key server.pem \
  --tls-rsa-address 10.10.10.8 \
  --tls-rsa-port 443 \
  --tls-rsa-protocol http
```

RSA non funziona con TLS 1.3, (EC)DHE o sessioni senza RSA key exchange.

## JSON

```bash
python3 pic-up.py capture.pcapng --json > report.json
python3 pic-up.py events.log --json > log-report.json
```

Tra le sezioni disponibili ci sono `streams`, `xor`, `comments`, `covert`,
`images` e `log`.

## Limiti

- L’OCR può confondere `0/O` e `1/l/I`: verificare sempre l’immagine.
- Immagini frammentate con buchi nella cattura possono rimanere incomplete.
- Un canale covert segnalato è un candidato, non una prova.
- Una flag redatta o assente dagli artefatti non può essere inventata.
- La scansione grezza è limitata a 128 MiB; i payload decodificati vengono comunque analizzati.

## Test

```bash
python3 -m unittest -v test_pic_up.py
```

I test correnti coprono RC4, repeating-XOR, recupero automatico della chiave del
writeup, decoder Base64, ricerca flag, reassembly TCP, transcript TCP/UDP,
timeline, redazione credenziali, IOC e CLI JSON. La fixture UDP può essere
convertita in PCAP con `text2pcap` per un test end-to-end. Gli incrementi
pianificati sono tracciati in `ROADMAP.md`.
