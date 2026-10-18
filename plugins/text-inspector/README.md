# Text Inspector

Analisi passiva di testo, JSON, hex e file testuali: conteggio byte/righe, entropia
dei byte e anteprima limitata. Non interpreta il contenuto come codice né visita URL.

## Limiti

Le misure descrivono solo i byte visibili nel budget del job. Un input troncato viene
marcato `partial`; la vista di contenuto restituita è limitata a 16 KiB per non
duplicare l'intero asset nel risultato. Il decoder è scelto dal BOM (UTF-8/16/32),
altrimenti usa UTF-8; le sequenze invalide sono sostituite, dichiarate e rendono
parziale il risultato quando la preview non è decodificabile senza perdita. La tabella
righe indica offset assoluti in byte nella vista e mostra al massimo 200 righe. La
vista riga è indicata come parziale anche quando una riga supera 1.024 caratteri o
quando restano righe oltre le prime 200; lo stato compare nella UI. La scansione di
caratteri invisibili/control copre la sola anteprima, al massimo 100 occorrenze; con
sequenze invalide gli offset Unicode non vengono dichiarati.
Gli input inline in byte vengono analizzati come dati raw; stringhe e oggetti
mantengono la serializzazione UTF-8 progressiva e limitata.

Per nuove famiglie di contenuto aggiungere un matcher positivo e una presentazione
dichiarativa in `output_schema.json`; non allargare il matcher a tutti i file.
