# GitHappens

GitHappens — adapter Forensic Hub

Contratto e installazione: [guida plugin](../README.md).

Il codice originale e i test sono conservati senza modifiche in `src/`.
Il file `plugin.py` costituisce l’adapter; non modifica gli analizzatori originali.

L'adapter è selezionato per directory, archivi dichiarati e immagini disco, non per
ogni file binario. Gli errori e gli avvisi di una fase legacy mantengono il risultato
`partial`; l'assenza di findings non equivale a una scansione completa se mancano tool
opzionali o l'output supera il budget.
Il parser fallback degli oggetti loose Git legge lo zlib a blocchi da 64 KiB, limita
gli oggetti a 16 MiB e enumera al massimo 50.000 entry. Marca `partial` quando trova
oggetti malformati o raggiunge il limite di inventario; i link simbolici dentro
`objects/` vengono ignorati.
