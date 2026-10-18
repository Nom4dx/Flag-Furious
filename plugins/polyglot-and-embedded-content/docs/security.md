# Sicurezza

L'analisi è offline, senza root e senza esecuzione. Non vengono aperti link,
renderizzati HTML/PDF, invocati interpreti, lanciati SFX o eseguiti file estratti.

Per ZIP ogni nome viene normalizzato come percorso POSIX e sono rifiutati
assoluti, `..`, NUL, drive Windows e symlink. Sono applicati: 512 entry, 32 MiB
per membro, 128 MiB totali o output budget inferiore, rapporto massimo 100:1.
CRC errati non producono artefatti. Gli artifact name sono basename sanitizzati,
non vengono creati link e SHA-256 deduplica i byte.

Byte budget, timeout, CPU, memoria, file size e workspace sono anche imposti dal
worker isolato. Un limite raggiunto rende l'analisi `partial` e rimane visibile.

