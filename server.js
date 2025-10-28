import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import morgan from 'morgan';
import helmet from 'helmet';
import Database from 'better-sqlite3';
import ExcelJS from 'exceljs';
import dayjs from 'dayjs';
import ejsMate from 'ejs-mate';  

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// --- DB ---
const db = new Database(path.join(__dirname, 'timetracker.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    pin TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS time_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    date TEXT NOT NULL,                -- YYYY-MM-DD
    check_in TEXT,                     -- ISO timestamp
    check_out TEXT,                    -- ISO timestamp
    FOREIGN KEY(employee_id) REFERENCES employees(id)
  );
  CREATE TABLE IF NOT EXISTS breaks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL,
    start TEXT,                         -- ISO timestamp
    end TEXT,                           -- ISO timestamp
    FOREIGN KEY(entry_id) REFERENCES time_entries(id)
  );
`);

// Seed sample employees if empty
const countEmp = db.prepare('SELECT COUNT(*) as c FROM employees').get().c;
if (countEmp === 0) {
  db.prepare('INSERT INTO employees (name, pin, is_admin) VALUES (?, ?, ?)').run('Johannes', '1430', 1);
  db.prepare('INSERT INTO employees (name, pin, is_admin) VALUES (?, ?, ?)').run('Sophie', '1111', 0);
}

// --- Middleware ---
app.use(helmet({
  contentSecurityPolicy: false, // keep Tailwind CDN simple for MVP
}));
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

function getOrCreateTodayEntry(employee_id) {
  const date = todayStr();
  let entry = db.prepare('SELECT * FROM time_entries WHERE employee_id=? AND date=?').get(employee_id, date);
  if (!entry) {
    db.prepare('INSERT INTO time_entries (employee_id, date) VALUES (?, ?)').run(employee_id, date);
    entry = db.prepare('SELECT * FROM time_entries WHERE employee_id=? AND date=?').get(employee_id, date);
  }
  return entry;
}

function computeSummary(entryId) {
  const entry = db.prepare('SELECT * FROM time_entries WHERE id=?').get(entryId);
  const breaks = db.prepare('SELECT * FROM breaks WHERE entry_id=? ORDER BY id ASC').all(entryId);
  let workMinutes = 0;
  let breakMinutes = 0;

  if (entry.check_in && entry.check_out) {
    const start = dayjs(entry.check_in);
    const end = dayjs(entry.check_out);
    workMinutes = end.diff(start, 'minute');
  } else if (entry.check_in) {
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
app.get('/login', (req, res) => {
  const employees = db.prepare('SELECT id, name FROM employees ORDER BY name').all();
  res.render('login', { employees, error: null });
});
app.post('/login', (req, res) => {
  const { employee_id, pin } = req.body;
  const emp = db.prepare('SELECT * FROM employees WHERE id=?').get(employee_id);
  if (!emp || emp.pin != pin) {
    const employees = db.prepare('SELECT id, name FROM employees ORDER BY name').all();
    return res.status(401).render('login', { employees, error: 'Falsche PIN oder Nutzer.' });
  }
  req.session.user = { id: emp.id, name: emp.name, is_admin: !!emp.is_admin };
  res.redirect('/');
});
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/', requireAuth, (req, res) => {
  const entry = getOrCreateTodayEntry(req.session.user.id);
  const summary = computeSummary(entry.id);
  const now = dayjs();
  const breaksToday = db.prepare('SELECT * FROM breaks WHERE entry_id=?').all(entry.id);
  const checkedIn = !!entry.check_in;
  const checkedOut = !!entry.check_out;
  const onBreak = breaksToday.length > 0 && !breaksToday[breaksToday.length-1].end;

  res.render('index', {
    user: req.session.user,
    now,
    entry,
    summary,
    onBreak,
    checkedIn,
    checkedOut
  });
});

// Actions
app.post('/action/checkin', requireAuth, (req, res) => {
  const entry = getOrCreateTodayEntry(req.session.user.id);
  if (!entry.check_in) {
    db.prepare('UPDATE time_entries SET check_in=? WHERE id=?').run(nowISO(), entry.id);
  }
  res.redirect('/');
});

app.post('/action/checkout', requireAuth, (req, res) => {
  const entry = getOrCreateTodayEntry(req.session.user.id);
  if (entry.check_in && !entry.check_out) {
    // prevent checkout while a break is running
    const lastBreak = db.prepare('SELECT * FROM breaks WHERE entry_id=? ORDER BY id DESC LIMIT 1').get(entry.id);
    if (lastBreak && lastBreak.start && !lastBreak.end) {
      db.prepare('UPDATE breaks SET end=? WHERE id=?').run(nowISO(), lastBreak.id);
    }
    db.prepare('UPDATE time_entries SET check_out=? WHERE id=?').run(nowISO(), entry.id);
  }
  res.redirect('/');
});

app.post('/action/break/start', requireAuth, (req, res) => {
  const entry = getOrCreateTodayEntry(req.session.user.id);
  // only if checked in and not checked out
  if (entry.check_in && !entry.check_out) {
    const lastBreak = db.prepare('SELECT * FROM breaks WHERE entry_id=? ORDER BY id DESC LIMIT 1').get(entry.id);
    if (!lastBreak || lastBreak.end) {
      db.prepare('INSERT INTO breaks (entry_id, start) VALUES (?, ?)').run(entry.id, nowISO());
    }
  }
  res.redirect('/');
});

app.post('/action/break/end', requireAuth, (req, res) => {
  const entry = getOrCreateTodayEntry(req.session.user.id);
  const lastBreak = db.prepare('SELECT * FROM breaks WHERE entry_id=? ORDER BY id DESC LIMIT 1').get(entry.id);
  if (lastBreak && lastBreak.start && !lastBreak.end) {
    db.prepare('UPDATE breaks SET end=? WHERE id=?').run(nowISO(), lastBreak.id);
  }
  res.redirect('/');
});

app.get('/history', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT te.*, 
      COALESCE((SELECT COUNT(*) FROM breaks b WHERE b.entry_id = te.id), 0) as pauses
    FROM time_entries te
    WHERE te.employee_id=?
    ORDER BY date DESC
    LIMIT 30
  `).all(req.session.user.id);
  const data = rows.map(r => {
    const s = computeSummary(r.id);
    return { ...r, ...s };
  });
  res.render('history', { user: req.session.user, data, dayjs });
});

// Admin: add employee
app.post('/admin/employees/add', requireAuth, requireAdmin, (req, res) => {
  const { name, pin, is_admin } = req.body;
  try {
    db.prepare('INSERT INTO employees (name, pin, is_admin) VALUES (?, ?, ?)').run(name.trim(), pin.trim(), is_admin ? 1 : 0);
  } catch (e) { /* ignore duplicate */ }
  res.redirect('/admin');
});

// Mitarbeiter aktualisieren
app.post('/admin/employees/update', requireAuth, requireAdmin, (req, res) => {
  const { id, name, pin, is_admin } = req.body;
  try {
    db.prepare('UPDATE employees SET name=?, pin=?, is_admin=? WHERE id=?')
      .run(name.trim(), pin.trim(), is_admin ? 1 : 0, id);
  } catch (e) {
    // optional: Fehlermeldung handhaben
  }
  res.redirect('/admin');
});

// Mitarbeiter löschen (optional)
app.post('/admin/employees/delete', requireAuth, requireAdmin, (req, res) => {
  const { id } = req.body;
  // Achtung: löscht NICHT die alten Zeiteinträge – bewusst getrennt halten
  try {
    db.prepare('DELETE FROM employees WHERE id=?').run(id);
  } catch (e) {}
  res.redirect('/admin');
});



// Admin panel
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  const employees = db.prepare('SELECT id, name, is_admin FROM employees ORDER BY name').all();
  res.render('admin', { user: req.session.user, employees });
});

// Admin export XLSX
app.get('/admin/export', requireAuth, requireAdmin, async (req, res) => {
  const { from, to } = req.query;
  const rows = db.prepare(`
    SELECT te.id, te.date, e.name as employee, te.check_in, te.check_out
    FROM time_entries te
    JOIN employees e ON e.id=te.employee_id
    WHERE te.date BETWEEN ? AND ?
    ORDER BY te.date ASC, e.name ASC
  `).all(from, to);

  const workbook = new ExcelJS.Workbook();
  const ws = workbook.addWorksheet('Zeiten');
  ws.columns = [
    { header: 'Datum', key: 'date', width: 12 },
    { header: 'Mitarbeiter', key: 'employee', width: 20 },
    { header: 'Check‑In', key: 'check_in', width: 22 },
    { header: 'Check‑Out', key: 'check_out', width: 22 },
    { header: 'Arbeitszeit (Min)', key: 'work', width: 18 },
    { header: 'Pausen (Min)', key: 'breaks', width: 16 },
    { header: 'Netto (Min)', key: 'net', width: 14 }
  ];

  for (const r of rows) {
    const s = computeSummary(r.id);
    ws.addRow({
      date: r.date,
      employee: r.employee,
      check_in: r.check_in || '',
      check_out: r.check_out || '',
      work: s.workMinutes,
      breaks: s.breakMinutes,
      net: s.netMinutes
    });
  }

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="export_${from}_${to}.xlsx"`);
  await workbook.xlsx.write(res);
  res.end();
});

// --- Start ---
app.listen(PORT, () => {
  console.log('TimeTracker listening on http://localhost:'+PORT);
});
