# Timely

Timely ist eine kleine Express/EJS-App zur Zeiterfassung. Der produktive Serverbetrieb nutzt PostgreSQL über `DATABASE_URL`.

Live-Adresse: [blank-timely.de/login](https://blank-timely.de/login). Der Render-Dienst [Timely](https://dashboard.render.com/web/srv-d409btk9c44c738o0qmg) ist mit `Luckyhanni/timely`, Branch `main`, verbunden. Automatische Veröffentlichung bei neuen Commits ist aktiviert (am 22.10.2026 geprüft). Render baut mit `npm install` und startet mit `node server.js`. Eine abweichende Domain kann über `APP_URL` eingestellt werden; ohne diese Variable verwendet der QR-Ausdruck `https://blank-timely.de`.

## Setup
1. Node.js 20 installieren.
2. Im Ordner `npm install` ausführen.
3. Für den produktiven Serverbetrieb `DATABASE_URL` und optional `SESSION_SECRET` setzen.
4. Start: `npm start` -> http://localhost:3000

Ohne `DATABASE_URL` startet Timely automatisch im öffentlichen Demo-Modus und leitet auf die statische Demo weiter.

## Verwaltung und Wochenübersicht

Unter `/admin` werden alle Mitarbeiter wochenweise (Montag bis Sonntag) angezeigt. Die Summe enthält abgeschlossene Netto-Arbeitszeiten. Offene Buchungen werden gesondert angezeigt und können über „Zeit korrigieren“ geschlossen werden. Beginn, Ende und eine optionale Gesamtpause können mit Begründung korrigiert oder fehlende Tage ergänzt werden. Eine leere Gesamtpause verwendet die tatsächlich erfassten Pausen. Offene Pausen werden beim nachgetragenen Check-out geschlossen; gespeicherte Pausen dürfen nicht außerhalb der korrigierten Zeit liegen. Vorher-/Nachher-Daten einschließlich Pausen, Admin und Zeitpunkt werden protokolliert. Parallele Änderungen derselben Buchung werden abgewiesen.

Mitarbeiter werden bei Austritt deaktiviert; historische Zeiten und Krankmeldungen bleiben erhalten. Eine leere PIN beim Bearbeiten behält die vorhandene PIN bei. Arbeitspläne sind im Adminbereich änderbar. Beim ersten Start der neuen Version werden vorhandene Mitarbeiter anhand ihres ersten Namens zugeordnet:

| Mitarbeiter | Regel |
| --- | --- |
| Sebastian, Andi, David | Montag bis Freitag |
| Theo | Montag bis Freitag; Mittwoch Berufsschule, während bayerischer Schulferien Arbeitstag |
| Babette | Dienstag bis Samstag |
| Jessica, Nina, Kilian, Luise | Aushilfe; keine gezählten Krankheitstage |
| Andere Namen | Plan muss im Adminbereich ausgewählt werden |

Es werden keine neuen Personenkonten oder PINs für diese Namen angelegt. Namenszuordnung und Arbeitsplan vor Benutzung prüfen. Änderungen eines Profils wirken auch auf die Auswertung bereits erfasster Krankmeldungen.

Krankheit wird ausdrücklich als Tagesstatus für einen Zeitraum erfasst. Fehlende Buchungen erzeugen keine Krankmeldung. Gezählt wird nur an geplanten betrieblichen Arbeitstagen; Aushilfen zählen auch mit einem einzelnen abweichenden Arbeitstag keine Krankheitstage. Urlaub, freie Tage und Berufsschule sind eigene Statuswerte. Für Feiertage, schulische Abweichungen oder ausgefallene Berufsschule kann der Plan tageweise überschrieben werden. Bei vorhandenem Zeiteintrag wird ein widersprüchlicher Abwesenheitsstatus abgewiesen; mehrtägige Änderungen erfolgen vollständig oder gar nicht.

Die Ferienzeiten stammen aus der [amtlichen bayerischen Ferienordnung](https://www.gesetze-bayern.de/Content/Document/BayVV_2230_1_1_0_K_13479/true) und sind bis einschließlich Sommer 2030 hinterlegt. Danach erscheint für betroffene Mittwoche „Ferien prüfen“, statt ungeprüft Krankheitstage zu zählen. Berufsschulen können abweichen; diese Ausnahmen im Tagesplan hinterlegen. Berufsschulstunden und Krankheitsstunden werden ohne vereinbarte Sollstunden nicht als Arbeitsstunden erfunden. Die Wochenübersicht zeigt Krankheitstage der Woche und des zugehörigen ISO-Kalenderjahres. Beim Jahreswechsel umfasst die Jahressumme nur die Kalendertage dieses Jahres.

Der Excel-Export enthält Zeiten, Tagesstatus und Wochensummen des ausgewählten Zeitraums. Angebrochene Wochen enthalten nur Tage innerhalb des Exportzeitraums. Ein Export verändert keine Zeiten oder Pausen mehr; die bisherige automatische Ergänzung von Pausen beim Herunterladen entfällt.

## Ausgedruckter QR-Code und Vor-Ort-Buchung

Der Ausdruck enthält eine dauerhafte, zufällige URL. Die Anwesenheitsprüfung erfolgt serverseitig über die öffentliche IP-Adresse bzw. das IPv6-Netz des Betriebsanschlusses. Ein gespeicherter oder weitergegebener Code erlaubt außerhalb dieses Anschlusses keine Buchung. Ein Scan gibt eine einzelne Buchung für zwei Minuten frei; die Freigabe wird gemeinsam mit der Buchung atomar verbraucht. Auch parallele Anfragen können denselben Scan nicht doppelt verwenden. Ein neuer Ausdruck lässt sich im Adminbereich erzeugen; dadurch werden der alte Code und bisherige Scan-Freigaben ungültig.

1. Die **Serverversion mit PostgreSQL** bereitstellen, nicht nur die statische Demo. `DATABASE_URL`, eine zufällige `SESSION_SECRET` mit mindestens 32 Zeichen, `NODE_ENV=production` und die öffentliche HTTPS-Adresse als `APP_URL` setzen. Sitzungen werden in PostgreSQL gespeichert. Für eine leere Datenbank einmalig `INITIAL_ADMIN_NAME` und eine individuelle `INITIAL_ADMIN_PIN` setzen und nach dem ersten Start entfernen; es gibt keinen öffentlich bekannten Standard-Admin.
2. Bei Hosting hinter einem Reverse Proxy `TRUST_PROXY` auf die tatsächlich vertrauenswürdige Anzahl von Proxys einstellen. Der vorgeschaltete Dienst muss die Client-Adresse korrekt setzen. Keine ungeprüften Forwarding-Header akzeptieren und den App-Server nicht zusätzlich am Proxy vorbei öffentlich zugänglich machen. Siehe [Express: hinter Proxys](https://expressjs.com/en/guide/behind-proxies.html).
3. Im Betrieb mit dem vorgesehenen WLAN verbinden. In `/admin` den erkannten Anschluss prüfen und als erlaubte öffentliche IPv4-Adresse (vorzugsweise einzeln) bzw. das IPv6-Netz des Betriebs eintragen. Die lokale WLAN-Adresse wie `192.168.x.x` ist bei externem Hosting nicht die vom Server gesehene Adresse. IPv4 und IPv6 bei Bedarf beide hinterlegen. Aktivierung ist nur vom eingetragenen Anschluss aus möglich.
4. „Vor-Ort-Buchung verpflichtend aktivieren“ auswählen. Den Ausdruck über „QR-Code drucken“ öffnen, ausdrucken und im Betrieb aushängen. Eine Buchung aus dem WLAN und eine abgewiesene Buchung über Mobilfunk prüfen, bevor der Ablauf für alle eingeführt wird.

Mitarbeiter verbinden ihr Handy mit dem Betriebs-WLAN, scannen den Code mit der Kamera, melden sich mit Name/PIN an und bestätigen Einchecken, Auschecken oder Pause. Für jede Buchung ist ein neuer Scan nötig. Die Konto-Anmeldung zum Lesen der eigenen Historie und die Adminverwaltung bleiben von unterwegs erreichbar; Admin-Korrekturen werden protokolliert und benötigen keinen QR-Scan.

Die Ortsprüfung belegt den benutzten Anschluss, keine GPS-Position. Ein VPN ins Betriebsnetz würde ebenfalls zugelassen; deshalb dafür keinen Mitarbeiter-Fernzugang verwenden. Bei einer Änderung der öffentlichen IP-Adresse muss die erlaubte Adresse aktualisiert werden. Bei wechselnden Anschlüssen eine feste IP bzw. einen geeigneten stabilen Zugang mit dem Betreiber einrichten. Der Schalter ist nach der Migration zunächst aus, damit vor Einrichtung des Betriebsanschlusses niemand ausgesperrt wird. Wer keinen nutzbaren WLAN-Zugang hat, kann den Papiercode allein nicht für eine verlässliche Ortsprüfung verwenden.

Schemaänderungen sind additiv und werden beim Start in einer Transaktion ausgeführt. Vor dem Produktivupdate eine Datenbanksicherung erstellen. Die Veröffentlichung wird durch die GitHub-Verknüpfung im Render-Dienst ausgelöst: Ein Commit auf `main` startet automatisch Build und Deployment. Ein Pull Request auf einem anderen Branch veröffentlicht die Änderungen noch nicht live. Die Prüf-Workflow-Datei führt Tests und den Demo-Build aus, kein Deployment. Im verbundenen Render-Arbeitsbereich ist keine Render-PostgreSQL-Instanz sichtbar; eine vorhandene externe Datenbank wird weiterhin über `DATABASE_URL` angebunden.

## Prüfungen

`npm test` prüft Kalender, Arbeitspläne, Krankheitszählung, deutsche Ortszeiten einschließlich Zeitumstellung, Pausen und Netzfreigaben. Mit `TEST_DATABASE_URL` läuft zusätzlich die Integration gegen eine **separate, wegwerfbare Datenbank mit dem exakten Namen `timely_test`**. Dabei wird deren öffentliches Schema zurückgesetzt; niemals eine produktive Datenbank verwenden. Die Integration prüft die Migration des alten Schemas, Rechte, CSRF, Zeitkorrekturen, Konflikte, Export ohne Änderungen sowie QR- und Netzwerkzwang. GitHub Actions stellt dafür eine eigene PostgreSQL-Testdatenbank bereit.

## Demo-Version
Die öffentliche Demo läuft ohne Login, ohne Datenbank und ohne echte Nutzerdaten.
Sie enthält die Wochenansicht, Zeitkorrekturen und Krankheitszählung mit neutralen Beispielprofilen. Die Vor-Ort-Prüfung wird nur von der Serverversion durchgesetzt.

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
