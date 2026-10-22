import { dateKey, monday, addDays, weekNumber, profiles, statusLabels, plannedStatus, countsSick, summary as sharedSummary, fromLocal, localDateTime } from './rules.js';
const STORAGE_KEY = 'timely-public-demo-v1';
let selectedWeek = monday();
let demoEditor = null;

const state = {
  view: 'tracker',
  userId: 1,
  data: loadData()
};

function loadData() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) {
    try {
      const data=JSON.parse(stored);
      data.statuses ||= []; data.audit ||= [];
      data.employees.forEach(e=>e.schedule_profile ||= 'weekdays');
      return data;
    } catch {
      localStorage.removeItem(STORAGE_KEY);
    }
  }
  const data = seedData();
  saveData(data);
  return data;
}

function seedData() {
  const isoDate = offset => addDays(dateKey(),offset);
  const at = (date, hhmm) => fromLocal(`${date}T${hhmm}`);
  const yesterday = isoDate(-1);
  const twoDaysAgo = isoDate(-2);

  return {
    employees: [
      { id: 1, name: 'Demo Admin', is_admin: true, schedule_profile:'weekdays' },
      { id: 2, name: 'Mitarbeiter A', is_admin: false, schedule_profile:'tue_sat' },
      { id: 3, name: 'Mitarbeiter B', is_admin: false, schedule_profile:'apprentice' },
      { id: 4, name: 'Aushilfe C', is_admin: false, schedule_profile:'casual' }
    ],
    statuses: [], audit: [],
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
  return dateKey();
}

function nowISO() {
  return new Date().toISOString();
}

function formatTime(value) {
  if (!value) return '';
  return new Date(value).toLocaleTimeString('de-DE', { timeZone:'Europe/Berlin', hour: '2-digit', minute: '2-digit' });
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
  return sharedSummary(entry,entry?getBreaks(entry.id):[]);
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
  renderDemoWeek();
  document.getElementById('employeeRows').innerHTML = state.data.employees.map(employee => (
    `<div class="flex items-center justify-between gap-3 rounded border border-white/10 px-3 py-2">
      <div class="min-w-0 flex-1">
        <div class="font-semibold">${escapeHtml(employee.name)}</div>
        <div class="text-xs text-white/50">${employee.is_admin ? 'Admin' : 'Mitarbeiter'} · ${escapeHtml(profiles[employee.schedule_profile])}</div>
        <select aria-label="Arbeitsplan für ${escapeHtml(employee.name)}" class="mt-2 text-xs w-full max-w-full" data-profile="${employee.id}">${Object.entries(profiles).map(([key,label])=>`<option value="${key}" ${employee.schedule_profile===key?'selected':''}>${escapeHtml(label)}</option>`).join('')}</select>
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
  if(action==='checkin') {
    if(state.data.entries.some(e=>e.employee_id===getEmployee().id&&e.check_in&&!e.check_out)) return alert('Es gibt noch eine offene Buchung. Bitte in der Verwaltung korrigieren.');
    const status=state.data.statuses.find(s=>s.employee_id===getEmployee().id&&s.date===todayStr());
    if(status&&status.status!=='work') return alert('Für heute ist ein Tagesstatus hinterlegt. Bitte zuerst in der Verwaltung prüfen.');
  }
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
    is_admin: document.getElementById('newEmployeeAdmin').checked,
    schedule_profile:'unassigned'
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
  state.data.statuses = state.data.statuses.filter(status => status.employee_id !== employeeId);
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

function renderDemoWeek() {
  const dates=Array.from({length:7},(_,i)=>addDays(selectedWeek,i));
  const employeeOptions=state.data.employees.map(e=>`<option value="${e.id}">${escapeHtml(e.name)}</option>`).join('');
  const rows=state.data.employees.map(employee=>{
    let minutes=0,sick=0;
    const cells=dates.map(date=>{
      const entries=state.data.entries.filter(e=>e.employee_id===employee.id&&e.date===date);
      const status=state.data.statuses.find(s=>s.employee_id===employee.id&&s.date===date);
      const closed=entries.filter(e=>e.check_out).reduce((sum,e)=>sum+computeSummary(e).netMinutes,0);
      minutes+=closed; if(countsSick(employee.schedule_profile,date,status?.status,status?.planned_override)) sick++;
      const planned=plannedStatus(employee.schedule_profile,date,status?.planned_override);
      const label=status?statusLabels[status.status]:({work:'—',off:'Frei',school:'Berufsschule',flexible:'Flexibel',unassigned:'Plan fehlt',calendar_missing:'Ferien prüfen'})[planned];
      return `<td><button class="day-link text-left" data-edit-day="${date}" data-employee="${employee.id}">${escapeHtml(label)}${closed?`<strong class="block">${humanDuration(closed)}</strong>`:''}${entries.some(e=>e.check_in&&!e.check_out)?'<div class="status-open">Offen · korrigieren</div>':''}</button></td>`;
    }).join('');
    return `<tr><td><strong>${escapeHtml(employee.name)}</strong><div class="text-xs text-white/50">${escapeHtml(profiles[employee.schedule_profile])}</div></td>${cells}<td>${humanDuration(minutes)}</td><td>${employee.schedule_profile==='casual'?'—':sick}</td></tr>`;
  }).join('');
  const editorEmployee=demoEditor?.employeeId || state.data.employees[0].id;
  const editorDate=demoEditor?.date || selectedWeek;
  const entry=state.data.entries.find(e=>e.employee_id===editorEmployee&&e.date===editorDate);
  document.getElementById('demoWeek').innerHTML=`
    <div class="demo-card p-4 md:p-6">
      <div class="flex flex-wrap justify-between items-center gap-3 mb-3"><h2 class="font-semibold">Wochenübersicht · ${weekNumber(selectedWeek)}</h2><div class="flex gap-3"><button data-week-step="-7">← Vorige</button><button data-week-step="0">Diese Woche</button><button data-week-step="7">Nächste →</button></div></div>
      <label class="text-sm">Woche wählen <input id="demoWeekDate" type="date" value="${selectedWeek}" class="bg-transparent border rounded px-2 py-1"></label>
      <div class="overflow-x-auto mt-3"><table class="week-table"><thead><tr><th>Mitarbeiter</th>${dates.map((d,i)=>`<th>${['Mo','Di','Mi','Do','Fr','Sa','So'][i]}<br>${formatDate(d)}</th>`).join('')}<th>Netto</th><th>Krank</th></tr></thead><tbody>${rows}</tbody></table></div>
      <p class="text-xs text-white/50 mt-3">Nur abgeschlossene Buchungen zählen zur Wochensumme. Tag anklicken zum Korrigieren. Keine automatische Krankmeldung bei fehlenden Zeiten.</p>
    </div>
    <div class="grid xl:grid-cols-2 gap-6 mt-6">
      <form id="demoEntryForm" class="demo-card p-6 timely-form space-y-3">
        <h2 class="font-semibold">Zeit korrigieren</h2>
        <label>Mitarbeiter<select name="employee_id">${employeeOptions}</select></label>
        <input name="date" type="hidden" value="${editorDate}"><p class="text-sm text-white/60">${formatDate(editorDate)} · Tag in der Wochenübersicht auswählen. Beginn und Ende gehören zu diesem Tag.</p>
        <label>Beginn<input name="check_in" type="time" value="${entry?.check_in?localDateTime(entry.check_in).slice(11):'07:00'}" required></label>
        <label>Ende<input name="check_out" type="time" value="${entry?.check_out?localDateTime(entry.check_out).slice(11):''}"></label>
        <label>Pausen gesamt (Minuten, leer = erfasste Pausen)<input name="pause" type="number" min="0" value="${entry?.break_minutes_override??''}"></label>
        <label>Grund<input name="reason" required minlength="3" maxlength="500"></label><button class="btn-vintage rounded px-4 py-2">Zeit speichern</button>
      </form>
      <form id="demoStatusForm" class="demo-card p-6 timely-form space-y-3">
        <h2 class="font-semibold">Krankheit & Tagesplan</h2>
        <label>Mitarbeiter<select name="employee_id">${employeeOptions}</select></label>
        <div class="grid sm:grid-cols-2 gap-3"><label>Von<input name="from" type="date" value="${selectedWeek}" required></label><label>Bis<input name="to" type="date" value="${addDays(selectedWeek,6)}" required></label></div>
        <label>Status<select name="status">${Object.entries(statusLabels).map(([key,label])=>`<option value="${key}">${label}</option>`).join('')}<option value="clear">Eintrag entfernen</option></select></label>
        <label>Abweichender Plan<select name="planned_override"><option value="">Regulären Plan verwenden</option><option value="work">Arbeitstag</option><option value="school">Berufsschule</option><option value="off">Frei / Feiertag</option></select></label>
        <label>Grund<input name="reason" required minlength="3" maxlength="500"></label>
        <p class="text-xs text-white/50">Krankheit zählt nur an geplanten Arbeitstagen. Aushilfen zählen keine Krankheitstage. Ferienregel für den Auszubildenden: Bayern bis Sommer 2030.</p>
        <button class="btn-vintage rounded px-4 py-2">Status speichern</button>
      </form>
    </div>
    <details class="demo-card p-4 mt-6"><summary>Letzte Änderungen (${state.data.audit.length})</summary><div class="mt-3 space-y-2 text-sm">${state.data.audit.slice(-15).reverse().map(a=>`<div>${escapeHtml(a.kind)} · ${escapeHtml(a.date)} · ${escapeHtml(a.reason)}</div>`).join('')||'Noch keine Änderungen.'}</div></details>`;
  document.querySelector('#demoEntryForm [name=employee_id]').value=String(editorEmployee);
}
document.getElementById('demoWeek').addEventListener('click',event=>{
  const step=event.target.closest('[data-week-step]'),edit=event.target.closest('[data-edit-day]');
  if(step){selectedWeek=+step.dataset.weekStep?addDays(selectedWeek,+step.dataset.weekStep):monday();demoEditor=null;renderDemoWeek();}
  if(edit){demoEditor={employeeId:+edit.dataset.employee,date:edit.dataset.editDay};renderDemoWeek();document.getElementById('demoEntryForm').scrollIntoView({behavior:'smooth',block:'center'});}
});
document.getElementById('demoWeek').addEventListener('change',event=>{
  if(event.target.id==='demoWeekDate'){selectedWeek=monday(event.target.value);renderDemoWeek();}
  if(event.target.closest('#demoEntryForm') && ['employee_id','date'].includes(event.target.name)) {
    const form=event.target.form;demoEditor={employeeId:+form.elements.employee_id.value,date:form.elements.date.value};renderDemoWeek();
  }
});
document.getElementById('employeeRows').addEventListener('change',event=>{
  if(event.target.dataset.profile){state.data.employees.find(e=>e.id===+event.target.dataset.profile).schedule_profile=event.target.value;saveData();renderAdmin();}
});
document.getElementById('demoWeek').addEventListener('submit',event=>{
  event.preventDefault();const form=event.target,values=Object.fromEntries(new FormData(form)),employeeId=+values.employee_id;
  try {
    if(form.id==='demoEntryForm') {
      const start=fromLocal(values.date+'T'+values.check_in),end=values.check_out?fromLocal(values.date+'T'+values.check_out):null;
      if(dateKey(start)!==values.date || new Date(start)>new Date() || (end&&(new Date(end)<=new Date(start)||new Date(end)>new Date()||new Date(end)-new Date(start)>86400000))) throw new Error('Bitte Datum und Reihenfolge der Zeiten prüfen.');
      const status=state.data.statuses.find(s=>s.employee_id===employeeId&&s.date===values.date);
      if(status&&status.status!=='work') throw new Error('Bitte zuerst den Tagesstatus entfernen oder auf Arbeitstag setzen.');
      const entry=state.data.entries.find(e=>e.employee_id===employeeId&&e.date===values.date);
      if(state.data.entries.some(e=>e!==entry&&e.employee_id===employeeId&&e.check_in&&new Date(e.check_in)<(end?new Date(end):Infinity)&&(e.check_out?new Date(e.check_out):Infinity)>new Date(start))) throw new Error('Überschneidung mit einer anderen oder offenen Buchung.');
      const pause=values.pause===''?null:+values.pause;
      if(pause!==null&&(!Number.isInteger(pause)||pause<0||(end&&pause>minutesBetween(start,end)))) throw new Error('Ungültige Pausendauer.');
      const pauses=entry?getBreaks(entry.id):[];
      if(pauses.some(b=>new Date(b.start)<new Date(start)||(end&&(new Date(b.start)>new Date(end)||(b.end&&new Date(b.end)>new Date(end)))))) throw new Error('Vorhandene Pausen liegen außerhalb der neuen Zeit.');
      const updated={...(entry||{id:nextId(state.data.entries),employee_id:employeeId,date:values.date}),check_in:start,check_out:end,break_minutes_override:pause};
      state.data.audit.push({kind:'Zeitkorrektur',date:values.date,reason:values.reason,before:entry?{...entry}:null,after:{...updated}});
      if(entry) Object.assign(entry,updated); else state.data.entries.push(updated);
      if(end) pauses.filter(b=>!b.end).forEach(b=>b.end=end);
    } else if(form.id==='demoStatusForm') {
      if(values.to<values.from || values.to>addDays(values.from,366)) throw new Error('Zeitraum auf höchstens 367 Tage begrenzen.');
      const dates=[];for(let date=values.from;date<=values.to;date=addDays(date,1)) dates.push(date);
      if(!['work','clear'].includes(values.status)&&state.data.entries.some(e=>e.employee_id===employeeId&&dates.includes(e.date)&&e.check_in)) throw new Error('Im Zeitraum sind Arbeitszeiten vorhanden. Bitte zuerst prüfen.');
      dates.forEach(date=>{
        state.data.statuses=state.data.statuses.filter(s=>s.employee_id!==employeeId||s.date!==date);
        if(values.status!=='clear') state.data.statuses.push({employee_id:employeeId,date,status:values.status,planned_override:values.planned_override||null});
      });
      state.data.audit.push({kind:'Tagesstatus',date:values.from+' – '+values.to,reason:values.reason});
    }
    saveData();renderAdmin();
  } catch(error) {alert(error.message);}
});
