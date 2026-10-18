# Output

Ogni metadata contiene tipo, namespace/campo, valore raw e normalizzato, origine,
percorso interno, offset, dimensione, hash se disponibile, parser, decoder,
timestamp, confidenza e relazione con una flag. Le sezioni separano modulo e stato.
Finding, artefatti, timeline e flag sono aggregati anche nei campi standard del
contratto. `report.json` è un artefatto derivato e non contiene i byte originali.
Le visualizzazioni sono JSON per l'engine centrale: bar per modulo e timeline.
