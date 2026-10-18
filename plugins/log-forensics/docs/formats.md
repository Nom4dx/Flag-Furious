# Formati

Il detector combina header, parseabilità, delimitatori, timestamp e nomi campo.
Suricata richiede `event_type` e `flow_id`; Zeek JSON usa `ts` e `uid`; Zeek TSV
usa `#separator/#fields`; EVTX usa `ElfFile\0`; journal usa `LPKSHHRH`. XML
Windows viene interpretato per record Event. Una estensione non convalida mai il
formato e tutti i candidati restano nel report.
