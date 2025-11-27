import Database from "better-sqlite3";

const db = new Database("timetracker.db");

function logTable(name, rows) {
  console.log("\n===== ${name} =====");
  console.table(rows);
}

// Employees
const employees = db.prepare("SELECT * FROM employees").all();
logTable("Employees", employees);

// Work sessions
const sessions = db.prepare("SELECT * FROM work_sessions").all();
logTable("Work Sessions", sessions);

// Breaks
const breaks = db.prepare("SELECT * FROM breaks").all();
logTable("Breaks", breaks);

// All tables
const tables = db.prepare(
  "SELECT name FROM sqlite_master WHERE type='table'"
).all();
logTable("Alle Tabellen", tables);