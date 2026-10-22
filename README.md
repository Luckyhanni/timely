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

Die Zeitkorrektur zeigt den Tag fest an und verwendet nur Uhrzeitfelder für Beginn und Ende. Bei vorhandenen Buchungen bestimmt der ursprüngliche Beginn den Tag serverseitig; ein geändertes verstecktes Datumsfeld kann ihn nicht verschieben. Das Ende muss am selben Tag nach dem Beginn liegen. Für einen fehlenden Arbeitstag wird zuerst der Tag in der Wochenübersicht ausgewählt.

Für die ausdrücklich beauftragte Bereinigung alter offener Buchungen gibt es eine getrennte Admin-Vorschau unter „Altbuchungen pauschal ergänzen“. Sie enthält nur offene Buchungen bis zum gewählten Stichtag (standardmäßig heute). Der unveränderte Beginn wird um exakt 8 Stunden 30 Minuten ergänzt; 30 Minuten Gesamtpause ergeben 8 Stunden Nettozeit. Späte Altfälle können dabei ausdrücklich als Ausnahme bis zum Folgetag reichen. Diese pauschalen Ergänzungen sind Schätzungen und werden pro Buchung mit Vorher-/Nachher-Daten, Admin, Begründung und `estimated:true` protokolliert. Bereits abgeschlossene Einträge bleiben unverändert. Vorhandene Pausen bleiben dokumentiert; offene Pausen werden ohne negative Intervalle geschlossen. Bei Überschneidungen, zukünftigen Enden oder seit der Vorschau geänderten Daten wird die gesamte Ergänzung abgewiesen. Die Bereinigung ist eine ausdrückliche Admin-Aktion, keine automatische tägliche Ergänzung und keine Migration beim Serverstart.

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

Für den bestehenden Render-Dienst wurden am 22.10.2026 drei vorgeschaltete Stationen nachgewiesen; er benötigt `TRUST_PROXY=3`. Die auf Admins begrenzte Diagnose `/admin/network-info` zeigt die erkannte Client-Adresse, Socket-Adresse und ausschließlich gültige IP-Adressen der Forwarding-Kette. Bei Hosting-Änderungen neu abgleichen, statt die Anzahl ungeprüft zu übernehmen. `/network-status` zeigt anonym nur, ob Vor-Ort-Zwang aktiv ist und ob der eigene Anschluss zur Freigabe passt; Mitarbeiterdaten, Anschlussadressen, Freigabeliste und QR-Schlüssel werden dort nicht ausgegeben.

Mitarbeiter verbinden ihr Handy mit dem Betriebs-WLAN und scannen den Code mit der Kamera. Beim ersten Scan wählen sie ihren Namen, geben die persönliche PIN ein und lassen „Dieses persönliche Handy verknüpfen“ ausgewählt. Weitere Scans im selben Browser öffnen direkt ihr Konto. Sie bestätigen Einchecken, Auschecken oder Pause selbst; ein Scan allein erzeugt keine Arbeitszeit. Für jede Buchung ist ein neuer Scan nötig. Auf gemeinsam genutzten Geräten die Verknüpfung abwählen. Bei einem neuen, abgelaufenen oder gesperrten Gerät ist die PIN erneut erforderlich.

### Persönliche Geräte

Die Zuordnung verwendet einen zufälligen Schlüssel in einem langlebigen, ausschließlich vom Server lesbaren Cookie. Im Produktivbetrieb ist es ein `__Host-`-Cookie mit `Secure`, `HttpOnly`, `SameSite=Lax` und `Path=/`; die Datenbank enthält nur dessen SHA-256-Prüfsumme. Es werden keine Hardwarekennungen oder Browser-Fingerabdrücke gesammelt. Die Verknüpfung gilt ein Jahr und wird bei gültigen QR-Scans im Betriebsnetz verlängert. Löschen der Browserdaten, private Fenster oder ein anderer Browser erfordern eine neue PIN-Anmeldung. Die Handykamera deshalb immer im selben normalen Browser öffnen lassen.

Das Verknüpfen ist nur mit korrekter PIN und gültigem QR-Scan im freigegebenen Betriebsnetz möglich. Ein bereits verknüpfter Browser kann nicht stillschweigend einem anderen Konto zugeordnet werden. Dafür zunächst unter „Meine Geräte“ die bisherige Verknüpfung aufheben. „Abmelden“ beendet nur die Sitzung; die Verknüpfung bleibt für den nächsten QR-Scan erhalten. Unter „Meine Geräte“ können Mitarbeiter eigene Geräte sperren; der Admin kann unter „Verknüpfte Mitarbeitergeräte“ verlorene oder weitergegebene Geräte mit Begründung sperren. Sperrungen werden protokolliert und auf den nächsten authentifizierten Anfragen wirksam. Eine PIN-Änderung oder Kontodeaktivierung macht auch bestehende Sitzungen und alle Geräte des Kontos ungültig.

Automatische Geräte-Anmeldungen entstehen nur bei einem gültigen QR-Scan im Betriebsnetz. Auch danach wird bei jedem angemeldeten Aufruf und bei jeder Buchung der Betriebsanschluss geprüft. Für die Adminverwaltung ist zusätzlich eine PIN-Anmeldung nötig; die Geräteerkennung allein öffnet keine Verwaltungsrechte. Die manuelle PIN-Anmeldung zum Lesen der eigenen Historie und die Adminverwaltung bleiben von unterwegs erreichbar; Admin-Korrekturen werden protokolliert und benötigen keinen QR-Scan.

Die Ortsprüfung belegt den benutzten Anschluss, keine GPS-Position. Ein VPN ins Betriebsnetz würde ebenfalls zugelassen; deshalb dafür keinen Mitarbeiter-Fernzugang verwenden. Bei einer Änderung der öffentlichen IP-Adresse muss die erlaubte Adresse aktualisiert werden. Bei wechselnden Anschlüssen eine feste IP bzw. einen geeigneten stabilen Zugang mit dem Betreiber einrichten. Der Schalter ist nach der Migration zunächst aus, damit vor Einrichtung des Betriebsanschlusses niemand ausgesperrt wird. Wer keinen nutzbaren WLAN-Zugang hat, kann den Papiercode allein nicht für eine verlässliche Ortsprüfung verwenden.

Schemaänderungen sind additiv und werden beim Start in einer Transaktion ausgeführt. Vor dem Produktivupdate eine Datenbanksicherung erstellen. Die Veröffentlichung wird durch die GitHub-Verknüpfung im Render-Dienst ausgelöst: Ein Commit auf `main` startet automatisch Build und Deployment. Ein Pull Request auf einem anderen Branch veröffentlicht die Änderungen noch nicht live. Die Prüf-Workflow-Datei führt Tests und den Demo-Build aus, kein Deployment. Im verbundenen Render-Arbeitsbereich ist keine Render-PostgreSQL-Instanz sichtbar; eine vorhandene externe Datenbank wird weiterhin über `DATABASE_URL` angebunden.

## Prüfungen

`npm test` prüft Kalender, Arbeitspläne, Krankheitszählung, deutsche Ortszeiten einschließlich Zeitumstellung, Pausen und Netzfreigaben. Mit `TEST_DATABASE_URL` läuft zusätzlich die Integration gegen eine **separate, wegwerfbare Datenbank mit dem exakten Namen `timely_test`**. Dabei wird deren öffentliches Schema zurückgesetzt; niemals eine produktive Datenbank verwenden. Die Integration prüft die Migration des alten Schemas, Rechte, CSRF, Zeitkorrekturen, Konflikte, Export ohne Änderungen sowie QR- und Netzwerkzwang. Für persönliche Geräte werden Erstregistrierung, falsche PIN, verlorene Sitzung, neue Browser, abgelaufene Scans und Geräte, IPv4/IPv6, QR-Wechsel, Mitarbeiterzuordnung, Geräte-Sperrung, PIN-Wechsel, Kontodeaktivierung und die zusätzliche Admin-PIN geprüft. Ein zusätzlicher Server im Produktionsmodus prüft die sicheren Cookies hinter einem TLS-Proxy und eine erneute Anmeldung mit dem `__Host-`-Gerätecookie. GitHub Actions stellt dafür eine eigene PostgreSQL-Testdatenbank bereit.

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
