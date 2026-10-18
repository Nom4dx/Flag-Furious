# Binary Static Analysis

Plugin statico e read-only per Forensic Hub. Identifica eseguibili, firmware,
filesystem, archivi e dati raw senza avviare il campione. La pipeline separa
sempre cinque fatti diversi: firma trovata, struttura validata, intervallo
estratto, codice identificato e indicatore sospetto. Nessuno di questi produce
automaticamente un verdetto malware.

## Architettura

`plugin.py` orchestra fasi indipendenti. `format_registry.py` propone firme;
`magic_detection.py` valida struttura e confini; i parser ELF, PE/COFF e Mach-O
producono header, tabelle e regioni eseguibili; i parser firmware e filesystem
validano header bounded; `carving.py` salva solo intervalli validati;
`disassembler.py`, YARA e i tool locali sono arricchimenti opzionali. Tutti i
subprocess sono array allow-listed con `shell=False`, timeout e output limitato.

L'input è aperto soltanto in lettura. Gli output passano da `ArtifactManager`,
sono deduplicati SHA-256 e restano nella directory isolata del job. Un archivio
ZIP o PDF con cifratura strutturalmente confermata genera una richiesta al broker
`bruteforce`; l'analisi non tenta password autonomamente.

## Formati e livelli

I parser completi coprono ELF32/64, PE32/PE32+, COFF e Mach-O 32/64/FAT. I
validator bounded coprono UEFI FV, U-Boot legacy, FIT/DTB, Android boot,
SquashFS, CramFS, UBI/UBIFS, EROFS, ISO9660, CPIO, ZIP, gzip, xz, bzip2, PNG,
JPEG, PDF, RIFF, SQLite, Java class, WebAssembly, OLE, PCAP e PCAPNG. 7z, RAR,
zstd e LZ4 sono candidati conservativi quando il confine esatto non è ricavabile
senza un parser esterno. BSON, protobuf e MessagePack non hanno una magic
universale: vengono mostrati solo quando un parser dichiarativo o una struttura
coerente li conferma.

## Dipendenze

Non esistono dipendenze obbligatorie oltre al core del Forensic Hub. Moduli
opzionali: `python-magic`, `pefile`, `capstone`, `yara-python`. Tool opzionali:
`file`, `readelf`, `objdump`, `llvm-objdump`, `llvm-readobj`, `strings`, `binwalk`,
`yara`, `radare2`, `uefiextract`, `unsquashfs`, `dtc`, `7z`. Ghidra headless e
Kaitai possono essere aggiunti tramite adapter locali; non vengono invocati per
assenza di un contratto/versione configurata.

## Output

La dashboard espone identità e hash, detection con candidati respinti, header,
sezioni, segmenti, entrypoint, simboli, import/export, relocation, strings,
hexdump, entropia, compressione, indicatori di cifratura, embedded, overlay,
firmware, filesystem, disassembly, funzioni, YARA, finding e artefatti. Produce
`File Structure Graph` e `Code Analysis Graph` nel JSON dichiarativo dell'engine
2D. Il report completo viene salvato come artefatto JSON.

Esempio finding:

```json
{"type":"rwx_section","severity":"high","confidence":0.98,
 "offset":4096,"section":".text","explanation":"Sezione scrivibile ed eseguibile"}
```

Esempio intervallo validato:

```json
{"format":"png","start_offset":8192,"end_offset":9044,"validated":true,
 "boundary_method":"internal_structure","confidence":0.99}
```

## Sicurezza e limiti

Il plugin non esegue file, firmware, macro, script, shellcode o artefatti. Non usa
rete. Le firme false restano nella sezione Detection con stato `rejected`. Il
byte budget, 4.096 signature hit, 5.000 stringhe, 4.096 finestre di entropia,
20.000 istruzioni e 64 MiB per singolo carving limitano lavoro e output. Alta
entropia significa soltanto compressione, cifratura o casualità possibile.
Il risultato passa a `partial` quando una fase segnala copertura ridotta,
inclusi limiti di byte/output, parser non riusciti, tool o regole YARA non
disponibili e carving/archivi incompleti. Un arricchimento saltato perché non
applicabile al formato non è da solo un errore.
L'analisi UEFI non espande GUID compression internamente; APFS, YAFFS, UBIFS e
formati proprietari richiedono adapter specializzati per enumerare i file.

## Test e nuovi parser

`tests/` genera fixture deterministiche e verifica parser, confini, carving,
grafi, richiesta bruteforce, contratto JSON, immutabilità e loader. Per aggiungere
un formato: aggiungere una `FormatSignature`, implementare un validator che
restituisca confini verificati, aggiungere il parser opzionale in una fase isolata
e creare almeno una fixture valida e una falsa. Un validator non deve usare la
sola firma né restituire un limite oltre il byte budget.
