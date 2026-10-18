# HIDGrabber

`HIDGrabber` analizza catture PCAP/PCAPNG contenenti traffico USB HID. Calcola lo SHA-256 dell’evidenza, estrae i report binari, ricostruisce il testo delle tastiere, interpreta modifier e Alt-code, traccia il mouse e tenta di decodificare valori testuali annidati.

Il file originale è sempre letto senza essere modificato. Per impostazione predefinita il risultato viene mostrato soltanto nella CLI: non vengono creati file, cartelle, CSV, JSON, SVG o cache Python. Gli artefatti vengono scritti esclusivamente quando l’utente passa `--output-dir`.

Quando trova traffico HID, l’ordine della CLI è sempre:

1. dump completo dei byte nel formato `0x00 0x00 0x04 ...`;
2. conversione strutturale di ogni report tastiera o mouse;
3. eventi semantici keycode → usage → carattere/azione;
4. plaintext di tutti i layout provati;
5. tutte le decodifiche hex/Base64/Base32/binary/URL e UTF disponibili;
6. eventuali match CTF.

La conversione non dipende da `--flag-prefix`: il prefisso serve solamente a restringere i match. Senza prefisso vengono evidenziati automaticamente anche token generici come `RR{...}`, `TEAM{...}` o `CTF_NAME{...}`.

## Requisiti

- Python 3.11 o successivo;
- TShark;
- capinfos (facoltativo; senza il tool, alcune metadata non vengono raccolte);
- Scapy soltanto per eseguire i test.

```bash
tshark --version
capinfos --version
python3 HIDGrabber.py --version
```

## Analisi rapida

```bash
python3 HIDGrabber.py capture.pcapng
```

Analisi completa, sempre senza creare file:

```bash
python3 HIDGrabber.py capture.pcapng --all
```

Per salvare esplicitamente gli artefatti:

```bash
python3 HIDGrabber.py capture.pcapng --all --output-dir risultati-hid
```

## Artefatti opzionali

I file seguenti vengono prodotti soltanto con `-o DIR` o `--output-dir DIR`:

| File | Contenuto |
|---|---|
| `decoded.txt` | Plaintext ricostruito e decodifiche annidate |
| `hid-reports.csv` | Frame, timestamp, bus, device, endpoint, hex compatto e dump `0xNN` |
| `keyboard-events.csv` | Modifier, keycode, nome HID, carattere e azione |
| `mouse-events.csv` | Pulsanti, delta X/Y, rotella e coordinate cumulative |
| `mouse-path.svg` | Percorso del mouse; tratto rosso quando è premuto il tasto sinistro |
| `report.json` | Report strutturato completo |

Ogni artefatto mostrato nel report riceve dimensione, tipo e SHA-256.

## Database HID interno

[hid_database.py](./hid_database.py) contiene 256 voci, da `0x00` a `0xFF`, incluse:

- lettere, numeri e punteggiatura;
- Enter, Esc, Backspace, Tab e Space;
- frecce e tasti di navigazione;
- F1–F24;
- tastierino numerico;
- tasti internazionali e LANG;
- modifier sinistri e destri;
- nomi espliciti per usage riservati o non stampabili.

Sono disponibili i layout `us`, `uk` e `it`. Con `--layout auto`, tutti vengono provati e confrontati tramite un punteggio; il report conserva anche le alternative.

## Ricostruzione della tastiera

Il decoder gestisce:

- report Boot Keyboard da 8 byte;
- report ID opzionale da 9 byte;
- fino a sei tasti simultanei;
- Shift, Ctrl, Alt, AltGr e GUI;
- Caps Lock e Num Lock;
- Backspace applicato realmente al testo;
- Enter e Tab;
- shortcut come `[CTRL+C]`;
- report duplicati, producendo un evento soltanto quando un tasto passa da rilasciato a premuto;
- errori `ROLLOVER`, `POST_FAIL` e `ERROR_UNDEFINED`;
- Alt-code Windows, usando CP437 senza zero iniziale e CP1252 con zero iniziale.

Per impostazione predefinita vengono decodificati soltanto endpoint IN e trasferimenti interrupt, riducendo i falsi positivi causati da descriptor e pacchetti host-to-device.

## Encoding testuali

I keycode HID non sono UTF-8 o UTF-16: sono usage code numerici. Gli encoding vengono applicati dopo la ricostruzione, quando il testo digitato contiene valori codificati.

Il tool riconosce ricorsivamente, fino a tre livelli:

- hex continuo;
- byte `0xNN`;
- byte escapati `\xNN`;
- sequenze binarie da otto bit;
- Base64;
- Base32;
- percent/URL encoding.

I byte ottenuti vengono provati come:

- UTF-8 e UTF-8 con BOM;
- UTF-16 generico, LE e BE;
- UTF-32 generico, LE e BE;
- UTF-7;
- ASCII;
- Latin-1;
- Windows CP1252;
- DOS CP850;
- Mac Roman.

Ogni livello riporta catena di trasformazioni, lunghezza e SHA-256 dei byte decodificati.

## Mouse HID

I report Boot Mouse da 3 o 4 byte vengono interpretati come:

```text
buttons | X signed | Y signed | wheel signed
```

Con `--output-dir`, le coordinate cumulative vengono salvate in CSV e visualizzate in SVG. Questo è utile quando una challenge usa il mouse per disegnare una flag o interagire con una tastiera virtuale.

## Test

```bash
python3 -m unittest -v test_hidgrabber.py
```

La suite genera anche una vera cattura USBPcap temporanea e la analizza tramite TShark.

## Glossario completo dei comandi

### `PCAP`

Argomento obbligatorio. Accetta PCAP, PCAPNG e `.cap` riconosciuti tramite estensione o magic bytes.

```bash
python3 HIDGrabber.py keyboard.pcapng
```

### `--all`

Esegue ogni controllo autonomo disponibile:

- prova contemporaneamente tastiera e mouse;
- confronta i layout US, UK e italiano;
- prova tutti gli encoding testuali supportati;
- include trasferimenti USB non interrupt;
- include endpoint IN e OUT;
- conserva i marker dei tasti speciali;
- cerca flag con i prefissi comuni.

Non inventa prefissi, regex o filtri e non crea file senza `--output-dir`.

```bash
python3 HIDGrabber.py capture.pcapng --all
python3 HIDGrabber.py capture.pcapng --all --output-dir analisi-completa
```

### `-o DIR`, `--output-dir DIR`

Abilita la scrittura e imposta la cartella degli artefatti. Senza questa opzione il tool non crea alcun file.

```bash
python3 HIDGrabber.py capture.pcap -o risultati-hid
```

### `--layout auto|us|uk|it`

Seleziona il layout. `auto` prova tutti i layout interni.

```bash
python3 HIDGrabber.py capture.pcap --layout it
python3 HIDGrabber.py capture.pcap --layout us
```

### `--device-type auto|keyboard|mouse|all`

Sceglie i decoder HID. `all` tenta tastiera e mouse anche sugli stessi frame compatibili.

```bash
python3 HIDGrabber.py capture.pcap --device-type keyboard
python3 HIDGrabber.py mouse.pcapng --device-type mouse
python3 HIDGrabber.py mixed.pcapng --device-type all
```

### `--encoding auto|ENCODING`

Controlla l’encoding usato dopo hex/Base64/Base32/binary/URL decoding. `auto` prova tutti gli encoding supportati.

```bash
python3 HIDGrabber.py capture.pcap --encoding auto
python3 HIDGrabber.py capture.pcap --encoding utf-16-le
python3 HIDGrabber.py capture.pcap --encoding cp1252
```

### `-f PREFIX`, `--flag-prefix PREFIX`

Imposta il prefisso atteso della flag.

```bash
python3 HIDGrabber.py capture.pcap -f flag
python3 HIDGrabber.py capture.pcap --flag-prefix picoCTF
```

### `-p REGEX`, `--pattern REGEX`

Cerca una regex aggiuntiva nel plaintext e nelle decodifiche. È ripetibile.

```bash
python3 HIDGrabber.py capture.pcap \
  -p 'password\s*[:=]\s*\S+' \
  -p 'https?://\S+'
```

### `-Y FILTER`, `--filter FILTER`

Applica un display filter Wireshark aggiuntivo.

```bash
python3 HIDGrabber.py capture.pcap \
  -Y 'usb.device_address == 4 && usb.endpoint_address == 0x81'
```

Il filtro HID interno rimane attivo e viene combinato con `AND`.

### `--clean`

Rimuove dal plaintext i marker non testuali come `[LEFT]`, `[F1]` e `[ESC]`. Backspace, Caps Lock e Alt-code continuano a essere applicati.

```bash
python3 HIDGrabber.py capture.pcap --clean
```

### `--include-non-interrupt`

Tenta la decodifica anche sui trasferimenti USB non interrupt.

```bash
python3 HIDGrabber.py capture.pcap --include-non-interrupt
```

### `--include-outbound`

Include i report host-to-device. Normalmente sono esclusi perché possono contenere LED, configurazione o dati che non rappresentano tasti premuti.

```bash
python3 HIDGrabber.py capture.pcap --include-outbound
```

### `--timeout SECONDI`

Imposta il timeout della passata TShark.

```bash
python3 HIDGrabber.py capture-grande.pcapng --timeout 300
```

### `--force`

Permette di utilizzare una cartella non vuota indicata esplicitamente con `--output-dir`. Non è valido senza `--output-dir`.

```bash
python3 HIDGrabber.py capture.pcap -o risultati --force
```

### `--json`

Stampa il report JSON su standard output senza creare file. Per creare anche gli artefatti bisogna aggiungere `--output-dir`.

```bash
python3 HIDGrabber.py capture.pcap --json
python3 HIDGrabber.py capture.pcap --json > riepilogo.json
python3 HIDGrabber.py capture.pcap --json --output-dir artefatti
```

### `--color auto|always|never`

Controlla i colori ANSI del report testuale.

```bash
python3 HIDGrabber.py capture.pcap --color always
python3 HIDGrabber.py capture.pcap --color never
```

`--no-color` è l’alias compatibile con gli altri tool della suite per disabilitare i colori:

```bash
python3 HIDGrabber.py capture.pcap --no-color
```

### `--version`

Mostra la versione.

```bash
python3 HIDGrabber.py --version
```

### `-h`, `--help`

Mostra l’help sintetico della CLI.

```bash
python3 HIDGrabber.py --help
```

## Esempi completi

Tastiera italiana, ricerca di flag e password:

```bash
python3 HIDGrabber.py challenge.pcapng \
  --layout it \
  --device-type keyboard \
  -f flag \
  -p 'password\s*[:=]\s*\S+' \
  -o challenge-output
```

Analisi automatica di tastiera, mouse e encoding:

```bash
python3 HIDGrabber.py mixed-usb.pcapng \
  --layout auto \
  --device-type all \
  --encoding auto
```

Isolamento di un dispositivo specifico:

```bash
python3 HIDGrabber.py many-devices.pcapng \
  -Y 'usb.bus_id == 1 && usb.device_address == 7 && usb.endpoint_address == 0x81' \
  --layout us
```

Analisi più permissiva per una cattura atipica:

```bash
python3 HIDGrabber.py unusual.pcap \
  --include-non-interrupt \
  --include-outbound \
  --device-type all
```
