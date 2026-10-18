# Componenti frontend distribuiti localmente

Le copie sono incluse in `frontend/assets/vendor` per permettere l'uso offline.
Gli hash dei file distribuiti sono registrati in `frontend-vendor-inventory.json`.

| Componente | Origine | Licenza conservata |
| --- | --- | --- |
| Bootstrap 5.3.8 CSS | https://github.com/twbs/bootstrap/tree/v5.3.8 | BOOTSTRAP-LICENSE.txt (MIT) |
| Font Awesome Free 6.7.2, CSS e font solid | https://github.com/FortAwesome/Font-Awesome/tree/6.7.2 | FONTAWESOME-LICENSE.txt |
| Barlow, Latin normal 400/600 | Fontsource / Google Fonts Barlow | BARLOW-OFL.txt (SIL OFL 1.1) |
| IBM Plex Mono, Latin normal 400 | Fontsource / Google Fonts IBM Plex Mono | PLEX-MONO-OFL.txt (SIL OFL 1.1) |

Il CSS Font Awesome ha esclusivamente gli URL dei font riscritti per utilizzare
la directory locale. Non viene caricato JavaScript di terzi dal frontend.

I sorgenti RootRunners sono preservati nella loro forma originale. Il relativo
inventario è distinto da quello dei vendor frontend: `source-inventory.json`.
