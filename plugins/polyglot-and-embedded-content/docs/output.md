# Output

Il risultato segue il contratto hub: summary, status, confidence, findings,
sections, artifacts, derived_assets, visualizations, flags, timeline,
execution_events, logs, warnings, errors e metrics.

La visualizzazione `offset_map` usa `x=start` e `y=length`; il grafo usa nodi con
ID stabili e archi `contains`, `concatenated_after`, `overlaps`, `extracted` e
`contains_flag`. La palette viene scelta per nome e tradotta dal motore centrale,
quindi il plugin non può iniettare CSS.

Le sezioni della dashboard mostrano prima identità e formati validati, poi prove
e confini, oggetti, parser specifici, decoy, payload e flag. I dati raw sono
disponibili soltanto su apertura del dettaglio.

Gli offset dei flag hanno uno scope esplicito: `input` è relativo all'asset
originale, `artifact` è relativo all'artefatto identificato dal suo SHA-256 e
`decoded_payload` non presenta un offset sorgente artificiale. Per i payload
decodificati, `decoded_offset` localizza il match nel contenuto trasformato e
`source_offset` indica solo l'inizio del candidato codificato nell'input.

