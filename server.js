// server.js — Timely (PostgreSQL on Render)

import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import morgan from 'morgan';
import helmet from 'helmet';
import { Pool } from 'pg';
import ExcelJS from 'exceljs';
import dayjs from 'dayjs';
import ejsMate from 'ejs-mate';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// --- DB: Postgres Pool ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('sslmode=disable') ? false : { rejectUnauthorized: false }
});

// Ensure schema & seed
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS employees (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      pin  TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS time_entries (
      id SERIAL PRIMARY KEY,
      employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      check_in TIMESTAMPTZ,
      check_out TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS breaks (
      id SERIAL PRIMARY KEY,
      entry_id INTEGER NOT NULL REFERENCES time_entries(id) ON DELETE CASCADE,
      start TIMESTAMPTZ,
      "end" TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_time_entries_employee_date ON time_entries(employee_id, date);
    CREATE INDEX IF NOT EXISTS idx_breaks_entry ON breaks(entry_id);
  `);

  const { rows } = await pool.query(`SELECT COUNT(*)::int AS c FROM employees;`);
  if (rows[0].c === 0) {
    await pool.query(
      `INSERT INTO employees (name, pin, is_admin) VALUES
       ($1,$2,$3),($4,$5,$6) ON CONFLICT DO NOTHING;`,
      ['Johannes', '1430', true, 'Sophie', '1111', false]
    );
  }
}
await ensureSchema();

// --- Middleware ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.engine('ejs', ejsMate);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000*60*60*12 } // 12h
}));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) return res.status(403).send('Forbidden');
  next();
}

// --- Helpers ---
function todayStr() { return dayjs().format('YYYY-MM-DD'); }
function nowISO() { return dayjs().toISOString(); }

// get or create today's entry
async function getOrCreateTodayEntry(employee_id) {
  const date = todayStr(); // string "YYYY-MM-DD"
  let { rows } = await pool.query(
    `SELECT * FROM time_entries WHERE employee_id=$1 AND date=$2 LIMIT 1;`,
    [employee_id, date]
  );
  if (rows.length === 0) {
    await pool.query(
      `INSERT INTO time_entries (employee_id, date) VALUES ($1, $2);`,
      [employee_id, date]
    );
    ({ rows } = await pool.query(
      `SELECT * FROM time_entries WHERE employee_id=$1 AND date=$2 LIMIT 1;`,
      [employee_id, date]
    ));
  }
  return rows[0];
}

async function getBreaks(entryId) {
  const { rows } = await pool.query(
    `SELECT id, start, "end" FROM breaks WHERE entry_id=$1 ORDER BY id ASC;`,
    [entryId]
  );
  return rows;
}

async function getEntry(entryId) {
  const { rows } = await pool.query(`SELECT * FROM time_entries WHERE id=$1;`, [entryId]);
  return rows[0];
}

async function computeSummary(entryId) {
  const entry = await getEntry(entryId);
  const breaks = await getBreaks(entryId);
  let workMinutes = 0;
  let breakMinutes = 0;

  if (entry?.check_in && entry?.check_out) {
    const start = dayjs(entry.check_in);
    const end = dayjs(entry.check_out);
    workMinutes = end.diff(start, 'minute');
  } else if (entry?.check_in) {
    workMinutes = dayjs().diff(dayjs(entry.check_in), 'minute');
  }

  for (const b of breaks) {
    if (b.start && b.end) breakMinutes += dayjs(b.end).diff(dayjs(b.start), 'minute');
    else if (b.start) breakMinutes += dayjs().diff(dayjs(b.start), 'minute');
  }

  const net = Math.max(0, workMinutes - breakMinutes);
  return { workMinutes, breakMinutes, pausesCount: breaks.length, netMinutes: net };
}

// --- Routes ---
app.get('/login', async (req, res) => {
  const { rows: employees } = await pool.query(
    `SELECT id, name FROM employees ORDER BY name;`
  );
  res.render('login', { employees, error: null });
});

app.post('/login', async (req, res) => {
  const { employee_id, pin } = req.body;
  const { rows } = await pool.query(`SELECT * FROM employees WHERE id=$1;`, [employee_id]);
  const emp = rows[0];
  if (!emp || emp.pin !== pin) {
    const { rows: employees } = await pool.query(`SELECT id, name FROM employees ORDER BY name;`);
    return res.status(401).render('login', { employees, error: 'Falsche PIN oder Nutzer.' });
  }
  req.session.user = { id: emp.id, name: emp.name, is_admin: !!emp.is_admin };
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/', requireAuth, async (req, res) => {
  const entry = await getOrCreateTodayEntry(req.session.user.id);
  const summary = await computeSummary(entry.id);
  const now = dayjs();
  const breaksToday = await getBreaks(entry.id);
  const checkedIn = !!entry.check_in;
  const checkedOut = !!entry.check_out;
  const onBreak = breaksToday.length > 0 && !breaksToday[breaksToday.length-1].end;

  res.render('index', {
    user: req.session.user, now, entry, summary, onBreak, checkedIn, checkedOut
  });
});

// Actions
app.post('/action/checkin', requireAuth, async (req, res) => {
  const entry = await getOrCreateTodayEntry(req.session.user.id);
  if (!entry.check_in) {
    await pool.query(`UPDATE time_entries SET check_in=NOW() WHERE id=$1;`, [entry.id]);
  }
  res.redirect('/');
});

app.post('/action/checkout', requireAuth, async (req, res) => {
  const entry = await getOrCreateTodayEntry(req.session.user.id);
  if (entry.check_in && !entry.check_out) {
    const { rows: last } = await pool.query(
      `SELECT * FROM breaks WHERE entry_id=$1 ORDER BY id DESC LIMIT 1;`,
      [entry.id]
    );
    const lastBreak = last[0];
    if (lastBreak && lastBreak.start && !lastBreak.end) {
      await pool.query(`UPDATE breaks SET "end"=NOW() WHERE id=$1;`, [lastBreak.id]);
    }
    await pool.query(`UPDATE time_entries SET check_out=NOW() WHERE id=$1;`, [entry.id]);
  }
  res.redirect('/');
});

app.post('/action/break/start', requireAuth, async (req, res) => {
  const entry = await getOrCreateTodayEntry(req.session.user.id);
  if (entry.check_in && !entry.check_out) {
    const { rows: last } = await pool.query(
      `SELECT * FROM breaks WHERE entry_id=$1 ORDER BY id DESC LIMIT 1;`,
      [entry.id]
    );
    const lastBreak = last[0];
    if (!lastBreak || lastBreak.end) {
      await pool.query(`INSERT INTO breaks (entry_id, start) VALUES ($1, NOW());`, [entry.id]);
    }
  }
  res.redirect('/');
});

app.post('/action/break/end', requireAuth, async (req, res) => {
  const entry = await getOrCreateTodayEntry(req.session.user.id);
  const { rows: last } = await pool.query(
    `SELECT * FROM breaks WHERE entry_id=$1 ORDER BY id DESC LIMIT 1;`,
    [entry.id]
  );
  const lastBreak = last[0];
  if (lastBreak && lastBreak.start && !lastBreak.end) {
    await pool.query(`UPDATE breaks SET "end"=NOW() WHERE id=$1;`, [lastBreak.id]);
  }
  res.redirect('/');
});

app.get('/history', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM time_entries WHERE employee_id=$1 ORDER BY date DESC LIMIT 30;`,
    [req.session.user.id]
  );
  // compute summaries in JS (klein & simpel)
  const data = [];
  for (const r of rows) {
    const s = await computeSummary(r.id);
    data.push({
      id: r.id,
      date: dayjs(r.date).format('YYYY-MM-DD'),
      check_in: r.check_in ? dayjs(r.check_in).toISOString() : null,
      check_out: r.check_out ? dayjs(r.check_out).toISOString() : null,
      ...s
    });
  }
  res.render('history', { user: req.session.user, data, dayjs });
});

// Admin: add employee
app.post('/admin/employees/add', requireAuth, requireAdmin, async (req, res) => {
  const { name, pin, is_admin } = req.body;
  try {
    await pool.query(
      `INSERT INTO employees (name, pin, is_admin) VALUES ($1,$2,$3) ON CONFLICT (name) DO NOTHING;`,
      [name.trim(), pin.trim(), !!is_admin]
    );
  } catch {}
  res.redirect('/admin');
});

// Mitarbeiter aktualisieren
app.post('/admin/employees/update', requireAuth, requireAdmin, async (req, res) => {
  const { id, name, pin, is_admin } = req.body;
  try {
    await pool.query(
      `UPDATE employees SET name=$1, pin=$2, is_admin=$3 WHERE id=$4;`,
      [name.trim(), pin.trim(), !!is_admin, id]
    );
  } catch {}
  res.redirect('/admin');
});

// Mitarbeiter löschen
app.post('/admin/employees/delete', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.body;
  try {
    await pool.query(`DELETE FROM employees WHERE id=$1;`, [id]);
  } catch {}
  res.redirect('/admin');
});

// Admin panel
app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
  const { rows: employees } = await pool.query(
    `SELECT id, name, is_admin FROM employees ORDER BY name;`
  );
  res.render('admin', { user: req.session.user, employees });
});

// Admin export XLSX
app.get('/admin/export', requireAuth, requireAdmin, async (req, res) => {
  const { from, to } = req.query;

  // Alle Einträge im Zeitraum holen (inkl. employee & Checktimes)
  const { rows } = await pool.query(
    `SELECT te.id, te.date, te.check_in, te.check_out, e.name AS employee
       FROM time_entries te
       JOIN employees e ON e.id = te.employee_id
      WHERE te.date BETWEEN $1 AND $2
      ORDER BY te.date ASC, e.name ASC;`,
    [from, to]
  );

  // Helfer
  const toHours = m => (m / 60).toFixed(1);

  // Für jeden Tages-Eintrag: Regel prüfen & ggf. fehlende Pause automatisch ergänzen
  for (const r of rows) {
    if (!r.check_in || !r.check_out) continue; // unvollständiger Tag -> überspringen

    const grossMinutes = Math.max(0, dayjs(r.check_out).diff(dayjs(r.check_in), 'minute'));
    if (grossMinutes < 360) continue; // < 6h => keine Pflichtpause

    // Aktuelle Pausen aufsummieren
    const { rows: br } = await pool.query(
      `SELECT start, "end" FROM breaks WHERE entry_id = $1 ORDER BY id ASC;`,
      [r.id]
    );

    let breakMinutes = 0;
    for (const b of br) {
      if (b.start && b.end) breakMinutes += dayjs(b.end).diff(dayjs(b.start), 'minute');
    }

    // Falls noch laufende (offene) Pause existiert, sicherheitshalber beenden
    const last = br[br.length - 1];
    if (last && last.start && !last.end) {
      await pool.query(`UPDATE breaks SET "end" = $1 WHERE entry_id = $2 AND "end" IS NULL;`, [r.check_out, r.id]);
      // neu summieren
      const { rows: br2 } = await pool.query(
        `SELECT start, "end" FROM breaks WHERE entry_id = $1 ORDER BY id ASC;`,
        [r.id]
      );
      breakMinutes = 0;
      for (const b of br2) {
        if (b.start && b.end) breakMinutes += dayjs(b.end).diff(dayjs(b.start), 'minute');
      }
    }

    // Defizit ermitteln und ggf. Pause ergänzen (direkt vor Check-out)
    const deficit = Math.max(0, 30 - breakMinutes); // in Minuten
    if (deficit > 0) {
      const start = dayjs(r.check_out).subtract(deficit, 'minute').toISOString();
      const end   = dayjs(r.check_out).toISOString();
      await pool.query(
        `INSERT INTO breaks (entry_id, start, "end") VALUES ($1, $2, $3);`,
        [r.id, start, end]
      );
    }
  }

  // Nach evtl. Ergänzungen: Daten für den Export erneut laden (aktuelle Summen)
  const { rows: rowsForExport } = await pool.query(
    `SELECT te.id, te.date, te.check_in, te.check_out, e.name AS employee
       FROM time_entries te
       JOIN employees e ON e.id = te.employee_id
      WHERE te.date BETWEEN $1 AND $2
      ORDER BY te.date ASC, e.name ASC;`,
    [from, to]
  );

  // Excel erstellen (JETZT in Stunden)
  const workbook = new ExcelJS.Workbook();
  const ws = workbook.addWorksheet('Zeiten');
  ws.columns = [
    { header: 'Datum',             key: 'date',     width: 12 },
    { header: 'Mitarbeiter',       key: 'employee', width: 20 },
    { header: 'Check-In',          key: 'check_in', width: 12 },
    { header: 'Check-Out',         key: 'check_out',width: 12 },
    { header: 'Arbeitszeit (Std)', key: 'work',     width: 18 },
    { header: 'Pausen (Std)',      key: 'breaks',   width: 16 },
    { header: 'Netto (Std)',       key: 'net',      width: 14 }
  ];

  for (const r of rowsForExport) {
    // Zusammenfassung NACH eventuell eingefügter Pause berechnen
    const s = await computeSummary(r.id);
    ws.addRow({
      date: dayjs(r.date).format('YYYY-MM-DD'),
      employee: r.employee,
      check_in: r.check_in ? dayjs(r.check_in).format('HH:mm:ss') : '',
      check_out: r.check_out ? dayjs(r.check_out).format('HH:mm:ss') : '',
      work:   toHours(s.workMinutes),
      breaks: toHours(s.breakMinutes),
      net:    toHours(s.netMinutes)
    });
  }

  res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="export_${from}_${to}.xlsx"`);
  await workbook.xlsx.write(res);
  res.end();
});


// --- Start ---
app.listen(PORT, () => {
  console.log('Timely listening on http://localhost:'+PORT);
});
