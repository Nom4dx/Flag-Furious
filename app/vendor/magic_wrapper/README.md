# Magic Wrapper

`magic-wrapper` analizza file sospetti senza eseguirli. Calcola hash, identifica
magic byte e strutture interne, estrae metadati immagine e può riparare una
firma iniziale danneggiata creando sempre una copia separata.

## Uso rapido

Richiede Python 3.11 o successivo. `exiftool` è opzionale e amplia i metadati
estratti dalle immagini.

```bash
python3 app.py evidence.bin
python3 app.py evidence.bin --all
python3 app.py evidence.bin --expect SHA256 --json
python3 app.py damaged.png --repair -o repaired.png
```

Dopo l'installazione locale è disponibile il comando dedicato:

```bash
python3 -m pip install .
magic-wrapper evidence.bin --all
```

La riparazione è conservativa: viene proposta solo quando una struttura
supportata è validata indipendentemente dalla firma. Il file originale non è
mai modificato e un output esistente richiede `--force`.

## Verifica

```bash
pytest -q
python3 -m py_compile app.py
```
