# Text Inspector

# Text Inspector

Analisi passiva di testo, JSON, hex e file testuali: conteggio byte/righe, entropia
dei byte e anteprima limitata. Non interpreta il contenuto come codice né visita URL.

## Limiti

Le misure descrivono solo i byte visibili nel budget del job. Un input troncato viene
marcato `partial`; la vista di contenuto restituita è limitata a 16 KiB per non
duplicare l'intero asset nel risultato. Il conteggio righe considera CR/LF ASCII.

Per nuove famiglie di contenuto aggiungere un matcher positivo e una presentazione
dichiarativa in `output_schema.json`; non allargare il matcher a tutti i file.
