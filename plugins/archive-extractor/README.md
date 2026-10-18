# Archive Extractor

Estrae membri ZIP in artefatti derivati con nomi appiattiti, rifiuto di path traversal
e symlink, limite di 64 file esportati, massimo 16 MiB per membro e budget totale di
output. La lettura completa del membro permette alla libreria ZIP di verificare il
CRC prima di registrare l'artefatto.

Le firme nel prefisso sono soltanto candidate: l'indice ZIP viene validato durante
l'analisi. Con input troncato dal byte budget l'indice potrebbe non essere visibile e
il risultato è `partial`. I membri cifrati sono inventariati e producono una richiesta
di credenziale ZipCrypto o WinZip AES; non vengono dichiarati estratti.

Il numero massimo di righe di inventario e i limiti per rapporto di espansione sono
ancora in audit; l'inventario si ferma a 10.000 membri. Consultare il
[programma di rifacimento](../../docs/PLUGIN_REFACTOR_PROGRAM.md) per i limiti aperti.
