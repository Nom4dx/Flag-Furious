# Limiti conosciuti

Il parser interno non decompila e non pretende di ricostruire perfettamente CFG
con salti indiretti. Capstone effettua disassembly, non decompilazione. RAR/7z,
APFS, HFS+, YAFFS2, UBI/UBIFS e volumi UEFI compressi richiedono tool esterni per
estrazione completa. I formati privi di magic universale richiedono uno schema
Kaitai locale configurato. Certificati Authenticode sono inventariati ma la
verifica di trust richiede una policy e trust store espliciti.
