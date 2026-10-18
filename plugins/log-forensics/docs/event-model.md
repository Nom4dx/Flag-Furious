# Modello evento

Ogni evento contiene ID stabile, file, riga, offset, raw mascherato, timestamp raw
e UTC, timezone/confidenza, parser, tipo, azione, outcome, utente, IP, host,
processo, session/request/flow ID, `raw_fields` e `normalized_fields`. Il modello
si ispira a ECS ma non distrugge campi vendor. Il file originale conserva il raw
integrale autorizzato.
