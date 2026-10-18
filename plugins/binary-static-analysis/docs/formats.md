# Formati e parser

ELF usa ELF header, program header e section header; PE usa DOS/COFF header,
optional header, data directory e sezioni; Mach-O usa header e load commands con
segmenti e sezioni. Questa differenza è mantenuta nei parser e nello schema.
Firmware e filesystem sono validati con dimensioni, offset e checksum disponibili.
Una signature hit senza questi controlli resta un candidato respinto.

Livelli: `signature_found`, `structure_validated`, `extracted`, `code_region` e
`suspicious_indicator`. I livelli non sono intercambiabili.
