# GitHappens Forensics

Applicazione web autonoma, offline e read-only per immagini virtuali, filesystem
legacy, Git, Reference Diff, esportazioni Slack, cache e cronologie. Non importa,
non richiama e non modifica `pic-up`, DiskHunt o altri progetti della workspace.

## Avvio

```bash
docker compose up --build
```

Aprire `http://localhost:8081`. Il servizio usa una porta diversa da DiskHunt.

Avvio locale:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
GITHAPPENS_DATA_DIR=./data uvicorn picup_web.main:app --port 8081
```

Analisi senza browser:

```bash
githappens-case evidence.qcow2 --prefixes 'picoCTF,flag,HTB'
githappens-case suspect.zip --reference baseline.zip --regex 'CTF\{[^}]+\}'
```

## Pipeline e output

Ogni caso conserva la copia caricata in `evidence/` con permessi read-only e
produce `<input-stem>_githappens/`:

```text
files/  images/  objects/  qcow/  legacy/  git/  slack/
cache/  history/ diff/     timeline/ flag_candidates/ logs/
```

Il manifest registra MD5/SHA-1/SHA-256, dimensione, MIME, sorgente, percorso,
offset quando noto, dimensione, timestamp, metodo, modulo, stato e confidenza.
L'interfaccia offre stato live, sezioni per modulo, anteprima/download degli
artefatti, copia di flag/hash, rilancio selettivo, cancellazione confermata e
ritorno alla home.

## Moduli

- **Virtual/QCOW**: riconoscimento magic QCOW2, VMDK, VHD/VHDX, QED, ISO e RAW;
  `qemu-img info --backing-chain`, map JSON, snapshot e check senza `-r`;
  scansione dei backing layer disponibili e vista RAW generata da copia privata.
- **Legacy**: magic FAT/NTFS/exFAT/ext/HFS/ISO/floppy, `mmls`, `fsstat`, `fls`,
  `tsk_recover -e`, recupero allocato/cancellato e scansione raw multiencoding.
- **Git Forensics**: repository normali, bare e parziali; refs, reflog, commit,
  tree, blob, pack, unreachable/dangling, righe rimosse e recupero blob con
  `cat-file`. Fallback autonomo per loose objects zlib SHA-1/SHA-256.
- **Reference Diff**: file/directory, rename per hash, metadati, primo offset
  binario e unified diff; le righe rimosse entrano nella ricerca flag.
- **Slack**: utenti, canali, messaggi/thread, reaction, timestamp UTC/locale,
  allegati e cache JSON/LevelDB; token/cookie/sessioni sono redatti nella UI.
- **Cache/History**: Chrome/Chromium/Edge/Firefox/Safari/Electron, SQLite/WAL,
  pagine raw, cronologie browser, download e Bash/Zsh/Fish/PowerShell.
- **Flag scanner**: ASCII/UTF-8, UTF-16 LE/BE, Base64, hex, URL encoding,
  gzip/zlib/bzip2/xz, XOR singolo validato sul prefisso e flag tra chunk.
  Il prefisso inserito dall'utente viene sempre escapato letteralmente e
  trasformato dal backend in una regex completa; l'interfaccia ne mostra
  immediatamente l'anteprima. La regex manuale è soltanto un'opzione avanzata.

## Sicurezza

Non vengono effettuate connessioni applicative a Slack, GitHub o browser; non
si usano credenziali recuperate; nessun file viene eseguito; non si avviano VM;
non si monta l'evidenza; i nomi estratti sono sanificati e l'estrazione limita
profondità, quantità, dimensione per membro e totale. Docker elimina capability,
usa filesystem root read-only, `/tmp` `noexec`, limiti CPU/RAM/PID e volume dati
dedicato. La cancellazione risolve e rimuove soltanto la directory UUID del caso.

## Test

```bash
PYTHONPATH=backend pytest -q
```

Le fixture generano realmente: QCOW2 con backing, ext4 con file cancellato,
repository Git con commit unreachable, diff con riga rimossa, Slack export,
cache frammentata, History Chromium, shell Base64 e SQLite WAL. Le prime due
immagini ufficiali picoCTF 2026 possono essere eseguite esplicitamente con:

```bash
sh scripts/run_picoctf_regressions.sh
```

Non vengono scaricate durante i test ordinari (circa 132 MB ciascuna). Il terzo
URL fornito nella specifica è troncato e quindi non è riproducibile finché non
viene comunicato l'indirizzo completo.

## Limiti dichiarati

Il parsing autonomo copre loose object Git; OFS_DELTA/REF_DELTA e pack index sono
risolti dal binario Git. LevelDB/IndexedDB corrotti vengono scanditi e correlati
come frammenti, non ricostruiti semanticamente senza una libreria dedicata.
PhotoRec/TestDisk/Bulk Extractor sono rilevati come strumenti disponibili ma non
partono automaticamente: sono costosi e PhotoRec/TestDisk hanno flussi
interattivi. Una stringa XOR o ricostruita riceve confidenza inferiore e resta
sempre un candidato, mai una flag inventata.
