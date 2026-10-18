# Limiti conosciuti

- Analisi statica bounded: file oltre il budget risultano partial.
- Nessun rendering visuale; bianco-su-bianco e fuori pagina usano euristiche PDF.
- EXIF interno legge il primo IFD e tipi scalar; MakerNote/thumbnail complessi non
  sono decodificati integralmente.
- HEIC/AVIF/WebP/GIF hanno inventario parziale, senza parser completo dei metadata.
- PDF object parser non implementa cifratura, filtri multipli o xref repair.
- OLE dettagliato richiede `olefile`; macro sono solo rilevate.
- Brainfuck ha limiti di passi/output e non accetta input runtime.
- `confirmed` richiede una regola/prova esterna; il plugin produce candidate o
  high-confidence e non tratta il solo prefisso come certezza.
