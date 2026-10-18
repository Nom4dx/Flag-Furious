# Architettura
`Plugin` gestisce l'analisi normale dell'Hub; `Broker` offre `request_unlock` e un vault RAM con TTL. Gli adapter verificano la password mediante parser/CRC/struttura prima dell'estrazione. Candidate e wordlist sono stream deterministici deduplicati tramite SHA-256. Il risultato persistente contiene soltanto `secret_ref` e `********`.
