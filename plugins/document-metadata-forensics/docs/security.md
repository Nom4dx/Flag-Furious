# Sicurezza

L'originale è montato read-only dal core. I parser non eseguono macro, DDE,
JavaScript, Launch, formule, HTML, URL o file incorporati. ZIP usa path e symlink
checks; decompressione, numero oggetti, dimensioni e VM Brainfuck sono limitati.
Gli artefatti vengono scritti soltanto nel workspace isolato e sono deduplicati.
Un parser malformato produce warning/partial. Il sandbox mantiene rete e privilegi
disabilitati, oltre a timeout, CPU, memoria, file-size e output budget.
