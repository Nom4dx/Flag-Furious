# Architettura

La pipeline copia l'upload nella directory privata del caso, imposta la copia a
sola lettura e non monta mai l'evidenza. Ogni fase fallisce in modo isolato e
aggiorna atomicamente `manifest.json`.

```text
Upload → hash → recursive extraction
       → virtual image/QEMU → TSK legacy recovery → Git
       → Reference Diff → Slack → Cache/SQLite → History
       → global flag scan → ranking/manifest/UI
```

I moduli restituiscono dati strutturati; `CaseStore` assegna agli artefatti un
ID, SHA-256, provenienza, metodo, stato e confidenza. I comandi sono costruiti
come vettori argv e non passano da una shell. QEMU usa `info`, `map`, `snapshot
-l` e `check` senza riparazione. Una vista RAW viene creata soltanto partendo da
una copia privata della QCOW, mai usando l'evidenza come destinazione.

Git opera con `--git-dir`, `cat-file`, `ls-tree`, `log --reflog` e `fsck`; non
esegue checkout. Il parser indipendente valida loose object zlib e relativo
header. Packfile e delta sono delegati a Git/verify-pack quando Git è presente.
