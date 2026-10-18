# DiskHunt Web

DiskHunt Web è una pipeline web read-only per il triage di immagini disco, il recupero di artefatti e la ricerca automatica di flag CTF. Supporta immagini raw, compresse, segmentate, E01 e dischi virtuali. Il motore combina parser binari nativi, The Sleuth Kit e decompressione isolata; non monta né esegue mai il contenuto analizzato.

## Avvio rapido

Requisiti: Docker 24+ e Docker Compose v2.

```bash
cp .env.example .env
docker compose up --build
```

Aprire <http://localhost:8080>, scegliere un'immagine, indicare per esempio `picoCTF{` e avviare. Stato e contatori sono aggiornati con Server-Sent Events. I dati di ciascun job risiedono in una directory isolata nel volume `diskhunt-data`.

Per lo sviluppo locale:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
PYTHONPATH=backend uvicorn diskhunt.main:app --reload --port 8000

cd frontend
npm install
VITE_API_URL=http://localhost:8000 npm run dev
```

## Pipeline implementata

1. Upload streaming con limite e nome sanificato.
2. MD5, SHA-1 e SHA-256 dell'evidence originale.
3. Conservazione separata dell'originale e creazione di una copia di analisi raw; conversione E01/VHD/VMDK/QCOW2 quando i tool sono disponibili.
4. Parsing MBR/GPT/EBR, GPT primaria e backup, superfloppy FAT, gap non allocati, bounds e overlap.
5. Detection FAT12/16/32, exFAT ed ext2/3/4 tramite signature.
6. Parsing BPB FAT e superblock ext, con geometria e feature flags.
7. Enumerazione filesystem ricorsiva via `fls`; statistiche originali `fsstat` conservate nei log.
8. Recupero di file visibili e cancellati via `icat`/`icat -r`, inventory inode/journal e acquisizione `blkls` di slack e blocchi non allocati.
9. Catalogo artefatti con MIME reale, SHA-256, inode, partizione, stato, confidenza e provenienza completa.
10. Estrazione ricorsiva gzip, xz, ZIP, TAR, 7z/RAR e testo PDF, con limiti anti-bomb e traversal.
11. Ricerca flag ASCII/UTF-8/UTF-16, regex o lista prefissi, overlap tra chunk e ricostruzione ASCII-art chiaramente marcata come euristica.
12. Carving validato JPEG, PNG, GIF, PDF, ZIP, RAR, 7z, ELF, PE e SQLite; firme custom via API.
13. File browser, preview testo/immagini/PDF/binari, hex, download e relazioni tra archivi.
14. Casi persistenti con stop, resume, report e cancellazione atomica completa.

Il byte budget misura le letture investigative effettuate dal motore nativo e distingue byte logici, fisici, serviti dalla cache, hit/miss e richieste. Hashing iniziale e processi TSK sono riportati separatamente: essendo strumenti esterni, le loro letture interne non sono misurabili in modo affidabile. Alla saturazione di una fase, il motore conserva i risultati e termina con stato `PARTIAL`; un resume può assegnare un nuovo budget.

## API

```text
POST /api/jobs                         multipart: image, options JSON
GET  /api/jobs                         elenco casi
GET  /api/jobs/{id}                    stato/checkpoint
GET  /api/jobs/{id}/events             stream SSE
POST /api/jobs/{id}/cancel
POST /api/jobs/{id}/resume             multipart opzionale: budgets JSON
DELETE /api/jobs/{id}                  cancellazione completa del caso
GET  /api/jobs/{id}/partitions
GET  /api/jobs/{id}/filesystems
GET  /api/jobs/{id}/files
GET  /api/jobs/{id}/deleted
GET  /api/jobs/{id}/flags
GET  /api/jobs/{id}/carved
GET  /api/jobs/{id}/artifacts
GET  /api/jobs/{id}/artifacts/{path}/preview
GET  /api/jobs/{id}/artifacts/{path}/content
GET  /api/jobs/{id}/artifacts/{path}/hex
GET  /api/jobs/{id}/logs
GET  /api/jobs/{id}/hex?offset=0&length=512
GET  /api/jobs/{id}/report?format=json|csv|markdown|html|zip
GET  /api/jobs/{id}/artifacts/{file}
```

Esempio API:

```bash
curl -F image=@challenge.dd \
  -F 'options={"prefix":"picoCTF{","prefix_is_regex":false,"mode":"balanced"}' \
  http://localhost:8080/api/jobs
```

## Fixture e test

Generare immagini FAT32/ext4 realmente formattate, una variante gzip e segmenti:

```bash
sudo apt install dosfstools mtools e2fsprogs
make samples
make test
```

Per eseguire il motore reale su qualunque insieme di immagini, senza risposte o offset hardcoded:

```bash
PYTHONPATH=backend python scripts/regression_images.py disko-1.dd disko-3.dd.gz challenge.img
```

La suite copre parser MBR/GPT/GPT corrotta/EBR/superfloppy, FAT12/16/32, ext4, flag normale/divisa tra chunk/UTF-16/regex/ASCII-art, budget e cache, carving, estrazione annidata, protezione bomb/traversal, MIME, SSRF, filename malevoli e cancellazione completa del caso. Le regressioni manuali usano la pipeline reale e non contengono flag, inode o offset conosciuti.

## Sicurezza e limiti dichiarati

- Il container gira come UID non privilegiato, senza capability, con filesystem root read-only, `no-new-privileges`, limiti CPU/RAM/PID e `/tmp` `noexec`.
- Nessun mount automatico e nessuna esecuzione di artifact. I comandi TSK sono costruiti senza shell e con timeout.
- Download confinati alla directory artifact del job; nomi e path sono normalizzati.
- L'adapter di validazione NBD rifiuta endpoint locali/privati e resta disabilitato. Il trasporto NBD non è esposto nella v0.1.
- E01 usa `ewfexport`; i formati virtuali supportati sono identificati con `qemu-img info` prima della conversione in raw e falliscono esplicitamente se il convertitore manca o dichiara un backing file. VHD usa il formato QEMU `vpc`; sono accettati anche VHDX, VMDK, QCOW/QCOW2, VDI e QED.
- `jls` e `ils` vengono acquisiti nel log, ma il replay completo delle transazioni JBD2 resta un'evoluzione successiva. DiskHunt conserva sempre stati prudenti e non promuove output incompleti a `RECOVERED`.

Il report di esempio è in [`examples/report.json`](examples/report.json).
L'audit architetturale è in [`docs/TECHNICAL_PLAN.md`](docs/TECHNICAL_PLAN.md).
