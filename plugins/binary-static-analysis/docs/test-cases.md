# Casi di test

Le fixture sintetiche coprono ELF, PE, Mach-O, ZIP/PNG embedded, U-Boot, CPIO,
compressione, entropia, stringhe UTF-16, falsi marker e cifratura ZIP. I test
controllano anche che gli hash dell'originale non cambino, che i confini estratti
siano esatti e che il loader importi il plugin. Tool opzionali assenti producono
coverage ridotta senza bloccare il risultato.
