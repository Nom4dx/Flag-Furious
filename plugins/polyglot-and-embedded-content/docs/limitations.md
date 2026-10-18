# Limiti conosciuti

- L'estrazione interna è completa per ZIP; 7z, RAR, TAR, CPIO e OLE sono validati
  ma non tutti estratti dalla versione iniziale.
- ZIP cifrati richiedono una password e rimangono inventariati.
- RAR non calcola ancora il termine esatto di tutti i block type.
- PDF object stream con filtri multipli non viene decompresso; le firme raw al
  suo interno possono quindi restare invisibili.
- Java class usa la constant pool come prova ma il limite fisico può includere
  trailing data quando non è ricavabile senza interpretare tutte le attribute.
- ELF e Mach-O usano le tabelle dichiarate come limite minimo verificato; overlay
  specifici dei segmenti richiedono analyzer futuri.
- Il decoder XOR prova una sola chiave byte e solo quando trova un prefisso flag.
- Base58 viene accettato solo se il risultato è prevalentemente stampabile.

Ogni limite riduce la confidenza o produce un warning; non trasforma un marker
casuale in un formato validato.

