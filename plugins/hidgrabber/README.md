# HIDGrabber

Decodifica passiva di report USB HID in PCAP/PCAPNG: tastiera, mouse, layout e
catene di encoding. L'analisi non invia dati al dispositivo. `tshark` è richiesto;
`capinfos` è opzionale e la sua assenza riduce solo la metadata coverage.

Le corrispondenze vengono restituite come candidate con canale/layout di origine.
Sono inoltrati tutti i prefissi configurati dal job. Per PCAP oltre il byte budget
il report indica che i byte analizzati sono una vista parziale; hash e dimensione
dell'evidenza restano quelli calcolati durante l'acquisizione.

Per il layout selezionato, ogni segmento del testo ricostruito ha una riga in
`keyboard_text_sources`: intervallo `[text_start, text_end)` in code point Unicode,
frame, timestamp, canale USB e tasto HID che lo ha prodotto. Le cancellazioni
Backspace aggiornano il testo e la mappa insieme; l'Alt-code è attribuito al frame
che chiude la sequenza. I match includono intervalli in code point Unicode nel testo
indicato dalla loro fonte; occorrenze uguali su canali o posizioni diversi restano
distinte.

## Limiti

Il parser ricostruisce sequenze per canale e layout e mappa gli intervalli del
layout selezionato ai frame sorgente. Le decodifiche annidate riportano intervalli
relativi al proprio testo e la catena di trasformazione, senza ancora ricondurre
ogni byte decodificato al singolo tasto originario. Formati di report HID diversi
dai layout supportati sono riportati come diagnostica e non come prova di assenza
di input tastiera. La deduplicazione mantiene distinti bus, dispositivo, endpoint
e tipo di trasferimento anche quando frame e payload coincidono. Gli artefatti
scaricabili conservano SHA-256, asset genitore e contesto di origine; l'adapter
non esporta una seconda copia JSON integrale del risultato.
La sezione dashboard dell'analisi porta lo stesso stato `partial` del risultato
quando l'input, TShark o l'esportazione riducono la coverage.
