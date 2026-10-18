# Archive Extractor

Estrae membri ZIP in artefatti derivati con nomi appiattiti, rifiuto di path traversal
e symlink, limite di 64 file esportati, massimo 16 MiB per membro e budget totale di
output. La lettura completa del membro permette alla libreria ZIP di verificare il
CRC prima di registrare l'artefatto.

Le firme nel prefisso sono soltanto candidate: l'indice ZIP viene validato durante
l'analisi. Con input troncato dal byte budget l'indice potrebbe non essere visibile e
il risultato è `partial`. I membri cifrati sono inventariati e producono una richiesta
di credenziale ZipCrypto o WinZip AES; non vengono dichiarati estratti.

L'inventario si ferma a 10.000 membri e distingue estratti, cifrati, directory,
rifiutati e non estratti per limite o errore. Ogni riga include l'ID della fonte,
l'offset del local header, dimensioni dichiarate e CRC dell'indice; gli estratti
aggiungono SHA-256 dopo la verifica CRC. I warning sono limitati a 100 voci più
un riepilogo delle omissioni. Il parser preflight limita l'indice centrale a 4 MiB;
gli archivi ZIP64 sono supportati solo quando rientrano in questo limite. Consultare
il [programma di rifacimento](../../docs/PLUGIN_REFACTOR_PROGRAM.md) per i gate
ancora aperti.
