const STORAGE_KEY = 'timely-public-demo-v1';

const state = {
  view: 'tracker',
  userId: 1,
  data: loadData()
};

function loadData() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch {
      localStorage.removeItem(STORAGE_KEY);
    }
  }
  const data = seedData();
  saveData(data);
  return data;
}

function seedData() {
  const today = new Date();
  const isoDate = offset => {
    const d = new Date(today);
    d.setDate(d.getDate() + offset);
    return d.toISOString().slice(0, 10);
  };
  const at = (date, hhmm) => `${date}T${hhmm}:00.000`;
  const yesterday = isoDate(-1);
  const twoDaysAgo = isoDate(-2);

  return {
    employees: [
      { id: 1, name: 'Demo Admin', is_admin: true },
      { id: 2, name: 'Mitarbeiter A', is_admin: false },
      { id: 3, name: 'Mitarbeiter B', is_admin: false }
    ],
    entries: [
      { id: 1, employee_id: 1, date: yesterday, check_in: at(yesterday, '08:05'), check_out: at(yesterday, '16:20') },
      { id: 2, employee_id: 1, date: twoDaysAgo, check_in: at(twoDaysAgo, '08:30'), check_out: at(twoDaysAgo, '15:45') },
      { id: 3, employee_id: 2, date: yesterday, check_in: at(yesterday, '09:00'), check_out: at(yesterday, '17:10') }
    ],
    breaks: [
      { id: 1, entry_id: 1, start: at(yesterday, '12:10'), end: at(yesterday, '12:40') },
      { id: 2, entry_id: 2, start: at(twoDaysAgo, '12:00'), end: at(twoDaysAgo, '12:30') },
      { id: 3, entry_id: 3, start: at(yesterday, '13:05'), end: at(yesterday, '13:35') }
    ]
  };
}

function saveData(data = state.data) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

function nextId(items) {
  return items.reduce((max, item) => Math.max(max, item.id), 0) + 1;
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function nowISO() {
  return new Date().toISOString();
}

function formatTime(value) {
  if (!value) return '';
  return new Date(value).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
}

function formatDate(value) {
  return new Date(`${value}T12:00:00`).toLocaleDateString('de-DE', {
    weekday: 'short',
    day: '2-digit',
    month: '2-digit',
    year: 'numeric'
  });
}

function minutesBetween(start, end) {
  if (!start || !end) return 0;
  return Math.max(0, Math.round((new Date(end) - new Date(start)) / 60000));
}

function getEmployee() {
  return state.data.employees.find(employee => employee.id === state.userId) || state.data.employees[0];
}

function getTodayEntry(create = false) {
  const employee = getEmployee();
  const date = todayStr();
  let entry = state.data.entries.find(item => item.employee_id === employee.id && item.date === date);
  if (!entry && create) {
    entry = { id: nextId(state.data.entries), employee_id: employee.id, date, check_in: null, check_out: null };
    state.data.entries.push(entry);
    saveData();
  }
  return entry;
}

function getBreaks(entryId) {
  return state.data.breaks.filter(item => item.entry_id === entryId).sort((a, b) => a.id - b.id);
}

function computeSummary(entry) {
  if (!entry) return { workMinutes: 0, breakMinutes: 0, pausesCount: 0, netMinutes: 0 };
  const end = entry.check_out || nowISO();
  const workMinutes = entry.check_in ? minutesBetween(entry.check_in, end) : 0;
  const breaks = getBreaks(entry.id);
  const breakMinutes = breaks.reduce((sum, item) => sum + minutesBetween(item.start, item.end || nowISO()), 0);
  return {
    workMinutes,
    breakMinutes,
    pausesCount: breaks.length,
    netMinutes: Math.max(0, workMinutes - breakMinutes)
  };
}

function humanDuration(minutes) {
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

function setView(view) {
  state.view = view;
  document.querySelectorAll('.view').forEach(section => section.classList.add('hidden'));
  document.getElementById(`${view}View`).classList.remove('hidden');
  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.toggle('nav-active', link.dataset.view === view);
  });
  document.getElementById('pageTitle').textContent = {
    tracker: 'Zeiterfassung',
    history: 'Historie',
    admin: 'Demo-Verwaltung'
  }[view];
  render();
}

function renderEmployees() {
  const select = document.getElementById('employeeSelect');
  select.innerHTML = state.data.employees.map(employee => (
    `<option value="${employee.id}">${escapeHtml(employee.name)}</option>`
  )).join('');
  select.value = String(getEmployee().id);
  document.getElementById('sidebarUser').textContent = getEmployee().name;
}

function renderTracker() {
  const entry = getTodayEntry(false);
  const summary = computeSummary(entry);
  const breaks = entry ? getBreaks(entry.id) : [];
  const checkedIn = !!entry?.check_in;
  const checkedOut = !!entry?.check_out;
  const lastBreak = breaks[breaks.length - 1];
  const onBreak = !!lastBreak && !lastBreak.end;

  document.getElementById('statusBadge').textContent = !checkedIn
    ? 'Nicht eingecheckt'
    : checkedOut
      ? 'Ausgecheckt'
      : onBreak
        ? 'In Pause'
        : 'Eingecheckt';

  const buttons = [];
  if (!checkedIn) buttons.push('<button data-action="checkin" class="btn-vintage rounded px-4 py-2">Einchecken</button>');
  if (checkedIn && !checkedOut && !onBreak) buttons.push('<button data-action="breakStart" class="btn-rose rounded px-4 py-2">Pause starten</button>');
  if (checkedIn && !checkedOut && onBreak) buttons.push('<button data-action="breakEnd" class="btn-rose rounded px-4 py-2">Pause beenden</button>');
  if (checkedIn && !checkedOut) buttons.push('<button data-action="checkout" class="rounded px-4 py-2 bg-white/10 hover:bg-white/15">Auschecken</button>');
  if (checkedOut) buttons.push('<div class="text-white/50 py-2">Heute wurde bereits ausgecheckt.</div>');
  document.getElementById('actionButtons').innerHTML = buttons.join('');

  document.getElementById('breaksToday').innerHTML = breaks.length
    ? `<div>Anzahl Pausen: <strong>${breaks.length}</strong></div>`
    : '<div class="text-white/50">Noch keine Pausen erfasst.</div>';

  document.getElementById('summaryBox').innerHTML = [
    ['Gesamtzeit', humanDuration(summary.workMinutes)],
    ['Pausenzeit', humanDuration(summary.breakMinutes)],
    ['Anzahl Pausen', String(summary.pausesCount)],
    ['Arbeitszeit', humanDuration(summary.netMinutes)]
  ].map(([label, value]) => (
    `<div class="flex items-center justify-between"><div>${label}</div><div class="font-semibold">${value}</div></div>`
  )).join('');
}

function renderHistory() {
  const rows = state.data.entries
    .filter(entry => entry.employee_id === getEmployee().id)
    .sort((a, b) => b.date.localeCompare(a.date))
    .map(entry => {
      const summary = computeSummary(entry);
      return `<tr class="table-row">
        <td class="px-4 py-2">${formatDate(entry.date)}</td>
        <td class="px-4 py-2">${formatTime(entry.check_in)}</td>
        <td class="px-4 py-2">${formatTime(entry.check_out)}</td>
        <td class="px-4 py-2">${humanDuration(summary.workMinutes)}</td>
        <td class="px-4 py-2">${summary.breakMinutes}m</td>
        <td class="px-4 py-2">${humanDuration(summary.netMinutes)}</td>
      </tr>`;
    });
  document.getElementById('historyRows').innerHTML = rows.join('') || (
    '<tr class="table-row"><td class="px-4 py-3 text-white/50" colspan="6">Noch keine Demo-Einträge vorhanden.</td></tr>'
  );
}

function renderAdmin() {
  document.getElementById('employeeRows').innerHTML = state.data.employees.map(employee => (
    `<div class="flex items-center justify-between gap-3 rounded border border-white/10 px-3 py-2">
      <div>
        <div class="font-semibold">${escapeHtml(employee.name)}</div>
        <div class="text-xs text-white/50">${employee.is_admin ? 'Admin' : 'Mitarbeiter'}</div>
      </div>
      <button data-delete-employee="${employee.id}" class="rounded px-3 py-1 bg-white/10 hover:bg-white/15">Entfernen</button>
    </div>`
  )).join('');
}

function renderClock() {
  const t = new Date();
  document.getElementById('clockTime').textContent = t.toLocaleTimeString('de-DE');
  document.getElementById('clockDate').textContent = t.toLocaleDateString('de-DE', {
    weekday: 'long',
    day: '2-digit',
    month: 'long',
    year: 'numeric'
  });
}

function render() {
  renderEmployees();
  if (state.view === 'tracker') renderTracker();
  if (state.view === 'history') renderHistory();
  if (state.view === 'admin') renderAdmin();
}

function runAction(action) {
  const entry = getTodayEntry(true);
  const breaks = getBreaks(entry.id);
  const lastBreak = breaks[breaks.length - 1];
  if (action === 'checkin' && !entry.check_in) entry.check_in = nowISO();
  if (action === 'breakStart' && entry.check_in && !entry.check_out && (!lastBreak || lastBreak.end)) {
    state.data.breaks.push({ id: nextId(state.data.breaks), entry_id: entry.id, start: nowISO(), end: null });
  }
  if (action === 'breakEnd' && lastBreak && !lastBreak.end) lastBreak.end = nowISO();
  if (action === 'checkout' && entry.check_in && !entry.check_out) {
    if (lastBreak && !lastBreak.end) lastBreak.end = nowISO();
    entry.check_out = nowISO();
  }
  saveData();
  render();
}

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', () => setView(link.dataset.view));
});

document.getElementById('employeeSelect').addEventListener('change', event => {
  state.userId = Number(event.target.value);
  render();
});

document.getElementById('actionButtons').addEventListener('click', event => {
  const button = event.target.closest('[data-action]');
  if (button) runAction(button.dataset.action);
});

document.getElementById('addEmployeeForm').addEventListener('submit', event => {
  event.preventDefault();
  const nameInput = document.getElementById('newEmployeeName');
  const name = nameInput.value.trim();
  if (!name) return;
  const employee = {
    id: nextId(state.data.employees),
    name,
    is_admin: document.getElementById('newEmployeeAdmin').checked
  };
  state.data.employees.push(employee);
  state.userId = employee.id;
  nameInput.value = '';
  document.getElementById('newEmployeeAdmin').checked = false;
  saveData();
  render();
});

document.getElementById('employeeRows').addEventListener('click', event => {
  const button = event.target.closest('[data-delete-employee]');
  if (!button || state.data.employees.length === 1) return;
  const employeeId = Number(button.dataset.deleteEmployee);
  state.data.employees = state.data.employees.filter(employee => employee.id !== employeeId);
  state.data.entries = state.data.entries.filter(entry => entry.employee_id !== employeeId);
  const entryIds = new Set(state.data.entries.map(entry => entry.id));
  state.data.breaks = state.data.breaks.filter(item => entryIds.has(item.entry_id));
  state.userId = state.data.employees[0].id;
  saveData();
  render();
});

function resetDemo() {
  localStorage.removeItem(STORAGE_KEY);
  state.data = loadData();
  state.userId = 1;
  setView('tracker');
}

document.getElementById('resetDemo').addEventListener('click', resetDemo);
document.getElementById('resetDemoSide').addEventListener('click', resetDemo);

renderClock();
setInterval(renderClock, 1000);
setInterval(() => {
  if (state.view === 'tracker') renderTracker();
}, 30000);
setView('tracker');
