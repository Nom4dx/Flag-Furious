# Ext4atto

Adapter del motore DiskHunt per analisi di immagini disco, partizioni, filesystem,
file cancellati, carving e recupero. Lo stato è parziale se si esaurisce il budget,
si omettono artefatti o mancano strumenti necessari come `mmls`.

## Integrazione 1.1 — immagini complete e recupero

L'adapter usa l'immagine autorizzata completa in sola lettura (`input_access:
random_access`): il budget di scansione non tronca più il filesystem ai primi
64 MiB. Gli altri plugin conservano la vista limitata predefinita. Non vengono
più create due copie raw nel workspace; decompressione e conversione producono
invece una copia separata, senza modificare l'evidenza originale.

Il workspace temporaneo di Ext4atto è limitato a 1 GiB, ulteriormente riducibile
con `HUB_MAX_WORKSPACE_BYTES`. Il limite di esportazione resta distinto (64 MiB
per impostazione predefinita). Se gli artefatti superano questo limite, vengono
privilegiati i file recuperati rispetto ai dump di slack/spazio non allocato:
le flag e il catalogo restano disponibili e il risultato diventa `partial`.

Le flag native sono trasferite al campo `flags` dell'hub, con confidenza 0–1,
provenienza e offset. Gli artefatti riportano anche l'asset genitore, il percorso
filesystem e l'offset assoluto quando il parser li conosce. Sono mantenuti anche i
risultati `recovered` e il catalogo entro i limiti dichiarati; le omissioni sono
segnalate. I log del risultato hub conservano gli ultimi 1.000 record e limitano
messaggio, comando e output grezzo a 512, 1.024 e 4.096 caratteri. Conteggio e
troncamento sono dichiarati nelle metriche e nelle righe; l'endpoint locale dei log
supporta `limit` e `offset`. I prefissi predefiniti includono quelli del tool
originale, compresi `FLAG{` e `SRDNLEN{`; un elenco personalizzato li sostituisce.
Sono riconosciuti anche input gzip/xz/zstd e superblock ext senza estensione nota.
Le immagini virtuali dirette o compresse sono identificate con `qemu-img info`
prima della conversione; i backing file non vengono seguiti. I formati vhd/vpc,
vhdx, vmdk, qcow, qcow2, vdi e qed usano il format rilevato, non una traduzione
presunta dall'estensione. E01 compresso non è dichiarato supportato.
La scansione di flag sugli artefatti catalogati legge blocchi da 1 MiB, fino a
64 MiB e 10.000 finding per file. L'API e i report registrano byte esaminati,
conteggio finding e stato `complete`, `partial` o `skipped_size_limit`; scansioni
limitate aggiungono un warning al job, la tabella Markdown mostra la copertura e
`GET /api/jobs/{id}/artifacts?scan_status=partial` filtra gli artefatti incompleti.
L'export ZIP del caso usa uno spool che passa su disco oltre 8 MiB e rifiuta
archivi oltre 64 MiB o 50.000 voci (HTTP 413); symlink e percorsi fuori dalla root
degli artefatti non vengono inclusi.

Il triage globale riserva budget ai plugin selezionati. Le letture investigative
native rispettano il budget ricevuto; hashing e letture interne di TSK, come nel
tool originale, non sono misurate da quel contatore. La disponibilità dell'intera
immagine non equivale a una scansione esaustiva: timeout, CPU e budget delle fasi
restano attivi. Per analisi lunghe configurare `HUB_TIMEOUT` e i limiti del manifest;
il valore effettivo è il più restrittivo. Immagini segmentate richiedono ancora
una preparazione esplicita: il plugin non riceve automaticamente i file vicini.

Verifica: `python -m pytest tests/test_ext4atto.py -v` confronta il plugin con il
motore originale usando una partizione ext4 a 80 MiB, un file cancellato e un ZIP
annidato; verifica inoltre gzip, budget di esportazione e integrità dell'originale.
Richiede `mkfs.ext4`, `debugfs` e The Sleuth Kit. Nessun mount viene effettuato.
