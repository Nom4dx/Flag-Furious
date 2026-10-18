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
Con la CLI Git disponibile, timeout, stdout troncato, inventari di oggetti/commit/tree
oltre i cap e letture blob fallite producono warning e integrità `partial`. I comandi
nel report sono riepilogati entro 2.000 righe con stato, byte raccolti e preview stderr;
`command_coverage` conta quelli omessi e lo stdout grezzo non viene duplicato. Senza
la CLI Git, il fallback marca sempre `partial`, perché non può esaminare refs, storia,
oggetti packed o linee rimosse.
Le anteprime degli artefatti testuali leggono al massimo 2 MiB e mostrano una nota
esplicita quando il contenuto supera tale limite.

Il riepilogo del caso conserva al massimo 50.000 finding e 100 warning distinti;
le coperture mostrano quanti elementi sono stati omessi. Un caso con warning,
errori di fase o coverage troncata termina con stato `partial`, che chiude anche
lo stream SSE. Nella scansione directory, warning, errori, stati parziali e contatori
di coverage annidati dei moduli vengono riportati anche al livello del plugin, così
il risultato non resta `completed` quando un analyzer ha avuto copertura incompleta.
I report dei moduli mantengono i dettagli specifici del modulo.
