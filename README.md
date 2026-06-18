# Timely

Timely ist eine kleine Express/EJS-App zur Zeiterfassung. Der produktive Serverbetrieb nutzt PostgreSQL über `DATABASE_URL`.

## Setup
1. Node.js 20 installieren.
2. Im Ordner `npm install` ausführen.
3. Für den produktiven Serverbetrieb `DATABASE_URL` und optional `SESSION_SECRET` setzen.
4. Start: `npm start` -> http://localhost:3000

Ohne `DATABASE_URL` startet Timely automatisch im öffentlichen Demo-Modus und leitet auf die statische Demo weiter.

## Demo-Version
Die öffentliche Demo läuft ohne Login, ohne Datenbank und ohne echte Nutzerdaten.

Lokal starten:

```bash
npm install
npm run build
npm run preview
```

Danach ist die Demo unter http://localhost:3000/demo.html erreichbar. Alternativ kann der Ordner `dist/` nach `npm run build` auf statischem Hosting wie Netlify, Vercel Static Output oder GitHub Pages veröffentlicht werden.

Die Demo verwendet neutrale Beispiel-Mitarbeiter und Beispiel-Zeiteinträge. Änderungen werden ausschließlich per `localStorage` im Browser gespeichert. Es sind keine echten Namen, Arbeitszeiten, PINs oder privaten Daten enthalten.

Demo zurücksetzen:

- In der App den Button `Demo zurücksetzen` verwenden.
- Oder im Browser den `localStorage`-Eintrag `timely-public-demo-v1` löschen.

In der öffentlichen Demo ist der echte Excel-Export deaktiviert und entsprechend gekennzeichnet.

## Hinweise
- PINs im produktiven Serverbetrieb sind aktuell einfache Textwerte. Vor produktiver Nutzung sollten PINs gehasht und Zugriff/Transport abgesichert werden.
- Lokale Datenbankdateien, Logs und `.env`-Dateien sind von der Veröffentlichung ausgeschlossen.
