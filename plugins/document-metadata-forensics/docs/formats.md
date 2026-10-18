# Formati

Le firme prevalgono sull'estensione. PDF: header, oggetti, stream Flate, EOF,
revisioni, OCG e azioni. Immagini: EXIF/TIFF, XMP, IPTC, PNG chunks, container
WebP/HEIC/AVIF e SVG statico. Office: inventario ZIP e XML OOXML/ODF/EPUB,
property files, commenti/revisioni/hidden state, macro e embedding. OLE usa
`olefile` opzionale. RTF rileva hidden text, field/DDE e object. HTML/MHTML/XML/
JSON sono convertiti in valori passivi; link e script non vengono aperti.
