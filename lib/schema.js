import { defaultProfile } from '../public/js/rules.js';
import { newQrToken } from './onsite.js';
export async function ensureSchema(pool) {
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    await db.query("SELECT pg_advisory_xact_lock(hashtext('timely-schema-v2'))");
    await db.query(`
      CREATE TABLE IF NOT EXISTS employees (id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, pin TEXT NOT NULL, is_admin BOOLEAN NOT NULL DEFAULT FALSE);
      CREATE TABLE IF NOT EXISTS time_entries (id SERIAL PRIMARY KEY, employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE, date DATE NOT NULL, check_in TIMESTAMPTZ, check_out TIMESTAMPTZ);
      CREATE TABLE IF NOT EXISTS breaks (id SERIAL PRIMARY KEY, entry_id INTEGER NOT NULL REFERENCES time_entries(id) ON DELETE CASCADE, start TIMESTAMPTZ, "end" TIMESTAMPTZ);
      ALTER TABLE employees ADD COLUMN IF NOT EXISTS schedule_profile TEXT;
      ALTER TABLE employees ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;
      ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS break_minutes_override INTEGER;
      ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 0;
      CREATE INDEX IF NOT EXISTS idx_time_entries_employee_date ON time_entries(employee_id,date);
      CREATE INDEX IF NOT EXISTS idx_breaks_entry ON breaks(entry_id);
      CREATE TABLE IF NOT EXISTS day_statuses (employee_id INTEGER NOT NULL REFERENCES employees(id), date DATE NOT NULL, status TEXT NOT NULL CHECK (status IN ('sick','leave','off','school','work')), planned_override TEXT CHECK (planned_override IN ('off','school','work')), revision INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (employee_id,date));
      CREATE TABLE IF NOT EXISTS audit_log (id SERIAL PRIMARY KEY, actor_id INTEGER, actor_name TEXT NOT NULL, employee_id INTEGER, kind TEXT NOT NULL, record_date DATE, before_data JSONB, after_data JSONB, reason TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value JSONB NOT NULL);
      CREATE TABLE IF NOT EXISTS onsite_grants (id TEXT PRIMARY KEY, qr_token TEXT NOT NULL, expires TIMESTAMPTZ NOT NULL);
    `);
    for (const employee of (await db.query('SELECT id,name FROM employees WHERE schedule_profile IS NULL')).rows) await db.query('UPDATE employees SET schedule_profile=$1 WHERE id=$2',[defaultProfile(employee.name),employee.id]);
    await db.query("ALTER TABLE employees ALTER COLUMN schedule_profile SET DEFAULT 'unassigned'");
    await db.query('ALTER TABLE employees ALTER COLUMN schedule_profile SET NOT NULL');
    const { rows } = await db.query('SELECT COUNT(*)::int AS count FROM employees');
    if (rows[0].count === 0 && process.env.INITIAL_ADMIN_PIN) {
      if (!/^\d{4,6}$/.test(process.env.INITIAL_ADMIN_PIN)) throw new Error('INITIAL_ADMIN_PIN muss 4–6 Ziffern haben.');
      await db.query("INSERT INTO employees(name,pin,is_admin,schedule_profile) VALUES($1,$2,TRUE,'unassigned')",[process.env.INITIAL_ADMIN_NAME || 'Admin',process.env.INITIAL_ADMIN_PIN]);
    }
    await db.query("INSERT INTO app_settings(key,value) VALUES('onsite',$1) ON CONFLICT DO NOTHING",[JSON.stringify({enabled:false,networks:'',token:newQrToken()})]);
    await db.query('COMMIT');
  } catch (error) { await db.query('ROLLBACK'); throw error; } finally { db.release(); }
}
