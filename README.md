# TimeTracker (Node + SQLite)
**Kostenlos, self‑hosted, mobil erreichbar.**

## Setup
1. Node.js LTS installieren.
2. Im Ordner: `npm install`
3. Start: `npm start` → http://localhost:3000
4. Default‑Nutzer: **Johannes / 1430 (Admin)**, **Sophie / 1111**.

## Zugriff von überall (ohne Port‑Forwarding)
**Cloudflare Tunnel (kostenlos)**:
- Cloudflare‑Account erstellen, eine Domain hinzufügen (auch kostenlose Subdomain via `cfpage`/`trycloudflare` möglich).
- Auf Windows: Cloudflare `cloudflared` installieren.
- Tunnel erstellen: `cloudflared tunnel login` → `cloudflared tunnel create timetracker` → `cloudflared tunnel route dns timetracker tracker.deinname.de`
- Konfig in `%USERPROFILE%\.cloudflared\config.yml`:
  ```yml
  tunnel: timetracker
  credentials-file: C:\Users\<USER>\.cloudflared\<id>.json
  ingress:
    - hostname: tracker.deinname.de
      service: http://localhost:3000
    - service: http_status:404
  ```
- Start: `cloudflared tunnel run timetracker`

## Backups
- SQLite Datei `timetracker.db` regelmäßig sichern (z. B. täglicher Windows Task, Kopie in OneDrive).

## Hinweise
- Dieses MVP speichert PINs **im Klartext** (für kleinen internen Einsatz ok). Für produktiv: PINs hashen (bcrypt) und HTTPS erzwingen.
- Optional: Roles/Abteilungen, verpflichtende Pausen, Rundungsregeln etc. sind einfach nachrüstbar.
