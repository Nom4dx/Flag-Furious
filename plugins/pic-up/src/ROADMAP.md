# pic-up — roadmap PCAP forensics

La roadmap è ordinata per impatto investigativo. Le funzioni automatiche devono
produrre evidenze riproducibili (frame, stream, endpoint e hash) e distinguere
sempre un'anomalia da una prova.

## P0 — fondamenta e ricostruzione

- [x] transcript TCP bidirezionali con anteprima testo/hex e frame sorgente;
- [x] ricostruzione per sequence number, deduplicazione di overlap e ritrasmissioni;
- [x] rilevamento challenge/response XOR con validazione su payload indipendente;
- [x] chiave repeating-XOR esplicita (`--xor-key`) e scansione dei plaintext;
- [x] test reali per crittografia, decoder, reassembly, stream e CLI;
- [x] transcript UDP per datagramma e pseudo-sessione;
- [ ] selezione/esportazione di un singolo stream in raw, hex e testo.

## P1 — triage forense ad alto impatto

- [x] timeline normalizzata dei pacchetti (report, CSV e JSONL);
- [x] inventario credenziali in chiaro per HTTP, FTP, SMTP, POP3, IMAP,
  Telnet e IRC, redatto per default;
- [x] inventario Wireshark Expert Info con frame, severità, gruppo e messaggio;
- [x] inventario ARP, ICMP/ICMPv6, DHCP, NTP, SMB, Kerberos e SSH;
- [ ] statistiche di upload/download, burst, idle time e cardinalità per host;
- [ ] rilevamento beaconing robusto (mediana/MAD oltre al coefficiente di variazione).

## P2 — IOC, fingerprint e ricerca

- [x] IOC deduplicati con first/last seen e frame: IP, dominio, URL ed email;
- [ ] fingerprint TLS JA3/JA4/JA3S, certificati, SSH HASSH e user-agent;
- [ ] correlazione DNS → IP → TLS SNI → HTTP Host nello stesso intervallo;
- [ ] allowlist/denylist locali e regole Sigma/YARA applicate agli artefatti;
- [ ] output SARIF/STIX 2.1 e baseline confrontabile tra due catture;
- [ ] ricerca entropy/sliding-window nei payload con offset riproducibile.

## P3 — protocolli cifrati, carving e anti-evasion

- [ ] known-plaintext XOR con offset, crib dragging e stima automatica del periodo;
- [ ] AES/ChaCha solo con parametri espliciti (mai indovinare modalità, nonce o padding);
- [ ] QUIC Initial metadata e integrazione keylog per HTTP/3 quando TShark lo supporta;
- [ ] ricomposizione IPv4/IPv6 fragment-aware e indicatori di overlap/evasion;
- [ ] carving MIME/mail, SMB, DICOM e file compressi aggiuntivi con limiti anti-bomb;
- [ ] verifica magic/MIME/estensione e report delle discrepanze;
- [ ] profilo `--safe` per limiti stretti e profilo `--deep` per analisi costosa.

## P4 — qualità e distribuzione

- [ ] completare la separazione del monolite (`capture`, `streams`, `crypto`,
  `carving`, `reporting`); gli analizzatori universali sono già in `picup/network.py`;
- [ ] fixture PCAP/PCAPNG minime generate deterministicamente;
- [ ] test di integrazione sulle versioni TShark supportate e CI;
- [ ] typing statico, lint, coverage e benchmark su catture grandi;
- [ ] report HTML standalone con navigazione stream/frame e nessuna risorsa remota;
- [ ] manifest del caso con hash di input, tool/versioni, opzioni e artefatti prodotti.
