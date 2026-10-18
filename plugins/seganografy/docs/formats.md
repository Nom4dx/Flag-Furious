# Formati
Il registro `signatures.py` separa sempre hit e formato validato. PNG usa chunk/CRC/IEND; JPEG segmenti/EOI; ZIP central directory/EOCD/CRC; PDF header/EOF; RIFF dimensione dichiarata. Altri container producono confini conservativi e confidence inferiore. Estensione e MIME sono soltanto evidenze, mai prova.
