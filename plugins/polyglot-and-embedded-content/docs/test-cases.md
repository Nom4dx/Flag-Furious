# Casi di test

Le fixture sintetiche hanno checksum e offset deterministici. I test coprono:

- PNG seguito da ZIP con flag in un membro;
- PDF seguito da ZIP e script seguito da ZIP/SFX;
- ZIP dentro un chunk PNG custom;
- firma ZIP casuale priva di EOCD;
- marker secondari distinti dalle radici;
- deduplica SHA-256 e nomi traversal;
- Zip Slip, symlink e rapporto archive bomb;
- flag presente soltanto dopo Base64;
- candidato respinto classificato come decoy;
- job hub completo con output mapping, grafici, download e originale immutato.

Nuovi validator devono aggiungere almeno una fixture valida, una troncata, una
con lunghezza/CRC errati e una firma casuale dentro dati ordinari.

