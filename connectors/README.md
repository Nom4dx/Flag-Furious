# Forensic Hub Connectors

I connector sono nodi dichiarativi per il workflow di estrazione. Ogni cartella contiene `connector.json`; il core associa il nodo a un plugin già isolato e ne valida asset, configurazione e segreti. Le password hanno `persist:false` e vengono inviate soltanto durante l'esecuzione.

Per aggiungere un connector definire ID, plugin, modalità, asset supportati, capacità di produrre asset e campi configurabili. Non inserire codice frontend nel connector e non richiedere rete o privilegi.

`bitlocker-readonly` inoltra password e recovery key come segreti effimeri al
plugin `encrypted-volume-forensics`. Produce una copia decifrata separata; non
monta il volume e non avvia automaticamente wordlist, John o Hashcat.
