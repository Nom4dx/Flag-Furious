# HIDGrabber

Decodifica passiva di report USB HID in PCAP/PCAPNG: tastiera, mouse, layout e
catene di encoding. L'analisi non invia dati al dispositivo. `tshark` è richiesto;
`capinfos` è opzionale e la sua assenza riduce solo la metadata coverage.

Le corrispondenze vengono restituite come candidate con canale/layout di origine.
Sono inoltrati tutti i prefissi configurati dal job. Per PCAP oltre il byte budget
il report indica che i byte analizzati sono una vista parziale; hash e dimensione
dell'evidenza restano quelli calcolati durante l'acquisizione.

## Limiti

Il parser ricostruisce sequenze per canale e layout; non associa ancora ogni
carattere decodificato a un singolo frame sorgente. Formati di report HID diversi
dai layout supportati sono riportati come diagnostica e non come prova di assenza
di input tastiera. La deduplicazione mantiene distinti bus, dispositivo, endpoint
e tipo di trasferimento anche quando frame e payload coincidono. Gli artefatti
scaricabili conservano SHA-256, asset genitore e contesto di origine; l'adapter
non esporta una seconda copia JSON integrale del risultato.
