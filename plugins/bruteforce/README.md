# Password Recovery / Brute Force

`bruteforce` è un nodo intermedio offline per artefatti locali protetti. Offre password nota, wordlist selezionate, trasformazioni opzionali, tentativi deterministici, pausa/ripresa/cancellazione nel broker, vault RAM con TTL e restituzione degli artefatti sbloccati. Non attacca servizi, account o autenticazioni remote.

## Flusso e contratto

I plugin dichiarano `unlock_capabilities` e invocano `Broker.request_unlock` con artefatto, tipo di protezione, plugin/run padre e adapter ammessi. Senza input il broker restituisce `waiting_for_user`. La password verificata resta nel `SecretVault`; JSON, log e audit contengono solo `secret_ref`, hash del candidato e `********`. L'analisi standard accetta le stesse opzioni in `plugin_options.bruteforce`.

## Wordlist portabili

Priorità: directory UI, `FORENSIC_HUB_WORDLIST_ROOT`, configurazione Hub, `./wordlists`, `./SecLists`, `./data/wordlists`. Nessun percorso assoluto è codificato. La UI mostra checkbox, ricerca, percorso relativo, byte, righe stimate e SHA-256. I file `.txt/.lst/.dic/.wordlist` sono montati singolarmente read-only nel sandbox e letti in streaming UTF-8/UTF-16 con fallback Latin-1. I candidati sono deduplicati tramite SHA-256.

## Adapter

- ZIP ZipCrypto con `zipfile`; ZIP AES con `pyzipper` opzionale.
- 7z/RAR con `7z`/`unrar` opzionali e test-before-extract.
- PDF con `pikepdf` o `qpdf` opzionali.
- Office Agile/Standard con `msoffcrypto-tool` opzionale.
- Steghide con CLI opzionale.
- XOR/testo cifrato per protezione dichiarata.
- OpenStego/StegCloak restituiscono uno stato esplicito quando non confermabili.

Un exit code zero non basta: l'adapter deve aprire, estrarre e validare struttura o CRC. Il risultato non viene eseguito.

## Sicurezza e limiti

Solo file regolari locali autorizzati. Niente rete, `shell=True`, macro, JavaScript, login o esecuzione di payload. Zip Slip, path assoluti, symlink e rapporti di espansione eccessivi sono bloccati. Tentativi, tempo, output e trasformazioni sono limitati; le trasformazioni sono disattivate per default. L'originale resta immutato.

## Estensione e test

Per aggiungere un adapter, estendere `PasswordAdapter`, implementare `can_handle`, `verify_password`, `extract`, `inspect_error`, `cleanup` e registrarlo in `adapter_registry.py`. Aggiungere fixture per password corretta/errata, corruzione, timeout, percorso ostile e validazione output. Eseguire `python -m pytest plugins/bruteforce/tests tests`.
