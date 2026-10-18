# Stato e ripresa del rifacimento Flag-Furious

Aggiornato il 18 ottobre 2026 su richiesta dell'utente. Fermarsi qui; riprendere
solo quando l'utente lo chiede.

## Checkout e rollback

- Checkout di lavoro: `/tmp/flag-furious-refactor`.
- Branch attivo: `forensic-plugin-refactor`.
- Remote: `git@github.com:Nom4dx/Flag-Furious.git`.
- `HEAD`, `origin/forensic-plugin-refactor` e `origin/main` sono allineati a
  `f630d06ecb1dc7ae9f8626d85dc0622679f66df4`.
- Worktree pulito al momento di questo handoff. Il checkout originale sotto
  `/home/nomad/Scrivania/Flag&Furious` è root-owned: non modificarlo; usare il
  checkout di lavoro indicato sopra.
- I commit Git sono il punto di rollback; modifiche pubblicate sia sul branch di
  refactor sia su `main`.

## Obiettivo ancora attivo

Rifare e verificare tutti i plugin esistenti in sequenza; solo dopo la chiusura
di A3 avviare i nuovi moduli della roadmap, mantenendo provenienza esplicita,
UI chiara, budget e stati parziali visibili. La richiesta di stop dell'utente è
temporanea: non chiude né riduce l'obiettivo.

## Ultimi interventi

- `f630d06 Make document offsets byte-accurate`: HTML/XML e SVG trovano le
  posizioni direttamente sui byte; gli offset numerici degli item, finding e
  artefatti del plugin documentale dichiarano `offset_scope: input`. README e
  programma di refactor aggiornati.
- `bec8deb Correct document finding byte provenance`: offset HTML/PDF/RTF
  esplicitati; indice Unicode OOXML separato dall'offset byte dell'header ZIP.
- `3ac0ea7 Navigate forensic findings to source bytes`: navigazione read-only
  limitata a scope sorgente espliciti.

Sui due ultimi cambiamenti documentali sono passati parse AST Python e
`git diff --check`; non sono state eseguite suite di test né verifiche runtime.

## Stato programma

- A0–A2 hanno interventi sostanziali registrati in
  `docs/PLUGIN_REFACTOR_PROGRAM.md`, ma i plugin sono ancora marcati
  `refactor`, non `done`.
- A3 **non è chiuso**: rimangono gate di fixture, contratto e runtime sui plugin
  esistenti; il programma enumera i debiti per plugin.
- `bruteforce` ha debito esplicito di gate fixture/runtime e compatibilità
  cross-platform del limite file.
- `host-artifact-forensics` esiste come prototipo anticipato, ma è differito.
  Non iniziare B1 o altri nuovi moduli prima della chiusura A3.
- Copertura del dominio, lacune e fasi B1–B5: `docs/FORENSIC_DOMAIN_ROADMAP.md`.

## Prossima ripresa

1. Rileggere questo file, `docs/PLUGIN_REFACTOR_PROGRAM.md` e
   `docs/FORENSIC_DOMAIN_ROADMAP.md`; verificare `git status` e allineamento
   remoto prima di modificare.
2. Continuare A3 sui plugin presenti: raccogliere evidenze per ogni gate, dare
   priorità ai debiti dichiarati nel registro e correggere i difetti concreti
   con commit piccoli e reviewabili.
3. Non dichiarare `done` senza evidenza adeguata di fixture, contratto e runtime;
   lasciare espliciti i gate che restano aperti.
4. Solo a A3 chiuso iniziare i moduli nuovi nell'ordine della roadmap.
5. Dopo ogni incremento stabile, aggiornare questo handoff/programmazione,
   committare e pushare su `forensic-plugin-refactor` e `main`.

