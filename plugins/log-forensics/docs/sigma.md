# Sigma locale

Le regole sono YAML locali, versionate e senza download durante l'analisi. Il
fallback interno valuta selection semplici e modificatori testuali. `condition`
complesse, aggregazioni e correlazioni native richiedono pySigma o tool esterni.
Ogni match conserva rule ID, titolo, livello, tag, false positive, reference,
campi ed eventi corrispondenti. Il fallback legge al massimo 1.000 regole e 256
KiB per file, enumera al massimo 10.000 directory, valuta non più di 10.000
eventi e 2.000.000 di coppie regola-evento, limita ogni regola a 128 selection
e il job a 5.000.000 di confronti di campo, e conserva 1.000 ID evento per
regola insieme al conteggio totale. Il superamento dei limiti è dichiarato come
warning del job, quindi il risultato è `partial`.
