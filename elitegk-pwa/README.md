# Elite GK - PWA (Cloudflare Pages + D1)
Struttura: index.html, sw.js, manifest.webmanifest, icon-192/512.png, schema.sql, functions/api/[[path]].js

## Deploy senza codice in locale
1. GitHub: crea un repo, "Add file > Upload files", trascina TUTTI i file e la cartella `functions` (estrai prima lo zip). Commit.
2. Cloudflare > Workers & Pages > Create > Pages > Connect to Git > scegli il repo. Build command: vuoto. Output directory: `/`. Deploy.
3. Cloudflare > Storage & Databases > D1 > Create database `elitegk` > Console > incolla `schema.sql` > Execute.
4. Pages project > Settings > Bindings > Add > D1 database: variable `DB` = elitegk (Production e Preview).
5. Pages project > Settings > Variables and secrets: `ADMIN_USER` = gaetano (testo) e `ADMIN_PASSWORD` = la tua password (tipo Secret). Opzionale: `REGISTRATION` = closed per chiudere le registrazioni.
6. Deployments > Retry deployment. Apri l'URL, accedi, poi Chrome > menu > Installa app.
La password admin non e' nel repo: per cambiarla modifica il secret e rifai il deploy.
