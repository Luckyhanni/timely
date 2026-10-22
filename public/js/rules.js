// Calendar rules are shared by the server and the public demonstration.
export const TZ = 'Europe/Berlin';
export const profiles = {
  weekdays: 'Montag bis Freitag',
  tue_sat: 'Dienstag bis Samstag',
  apprentice: 'Mo–Fr, Mittwoch Berufsschule (außer in den Ferien)',
  casual: 'Aushilfe · keine Krankheitstage',
  unassigned: 'Arbeitsplan noch festlegen'
};
export const statusLabels = { sick: 'Krank', leave: 'Urlaub', off: 'Frei', school: 'Berufsschule', work: 'Arbeitstag' };
// Bayerisches Kultusministerium, Ferienordnung 2024/25–2029/30, inkl. Sommer 2030.
// https://www.gesetze-bayern.de/Content/Document/BayVV_2230_1_1_0_K_13479/true
export const schoolHolidays = [
  ['2024-07-29','2024-09-09'],['2024-10-28','2024-10-31'],['2024-12-23','2025-01-03'],
  ['2025-03-03','2025-03-07'],['2025-04-14','2025-04-25'],['2025-06-10','2025-06-20'],
  ['2025-08-01','2025-09-15'],['2025-11-03','2025-11-07'],['2025-12-22','2026-01-05'],
  ['2026-02-16','2026-02-20'],['2026-03-30','2026-04-10'],['2026-05-26','2026-06-05'],
  ['2026-08-03','2026-09-14'],['2026-11-02','2026-11-06'],['2026-12-24','2027-01-08'],
  ['2027-02-08','2027-02-12'],['2027-03-22','2027-04-02'],['2027-05-18','2027-05-28'],
  ['2027-08-02','2027-09-13'],['2027-11-02','2027-11-05'],['2027-12-24','2028-01-07'],
  ['2028-02-28','2028-03-03'],['2028-04-10','2028-04-21'],['2028-06-06','2028-06-16'],
  ['2028-07-31','2028-09-11'],['2028-10-30','2028-11-03'],['2028-12-23','2029-01-05'],
  ['2029-02-12','2029-02-16'],['2029-03-26','2029-04-06'],['2029-05-22','2029-06-01'],
  ['2029-07-30','2029-09-10'],['2029-10-29','2029-11-02'],['2029-12-24','2030-01-04'],
  ['2030-03-04','2030-03-08'],['2030-04-15','2030-04-26'],['2030-06-11','2030-06-21'],
  ['2030-07-29','2030-09-09']
];
export function validDate(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(`${value}T12:00:00Z`).toISOString().slice(0,10) === value;
}
export function dateKey(value = new Date()) {
  if (validDate(value)) return value;
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year:'numeric', month:'2-digit', day:'2-digit' }).formatToParts(new Date(value)).map(p=>[p.type,p.value]));
  return `${parts.year}-${parts.month}-${parts.day}`;
}
export function addDays(date, count) {
  const d = new Date(`${date}T12:00:00Z`); d.setUTCDate(d.getUTCDate()+count);
  return d.toISOString().slice(0,10);
}
export function localDateTime(value) {
  const p=Object.fromEntries(new Intl.DateTimeFormat('en-CA',{timeZone:TZ,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date(value)).map(p=>[p.type,p.value]));
  return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}`;
}
export function fromLocal(value) {
  if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value) || !validDate(value.slice(0,10)) || +value.slice(11,13)>23 || +value.slice(14,16)>59) throw new Error('Ungültige Uhrzeit.');
  const target=Date.parse(value+':00Z'); let result=target;
  for(let i=0;i<4;i++) result+=target-Date.parse(localDateTime(result)+':00Z');
  if(localDateTime(result)!==value) throw new Error('Diese Uhrzeit existiert in deutscher Ortszeit nicht.');
  return new Date(result).toISOString();
}
export function monday(date = dateKey()) {
  if (!validDate(date)) throw new Error('Ungültiges Datum.');
  const day = new Date(`${date}T12:00:00Z`).getUTCDay();
  return addDays(date, -(day+6)%7);
}
export function weekNumber(date) {
  const thu = new Date(`${addDays(monday(date),3)}T12:00:00Z`);
  const first = new Date(`${thu.getUTCFullYear()}-01-01T12:00:00Z`);
  return `${thu.getUTCFullYear()} · KW ${Math.ceil(((thu-first)/86400000+1)/7)}`;
}
export function defaultProfile(name) {
  const first = name.trim().split(/\s+/)[0].toLowerCase();
  if (['sebastian','andi','andy','david'].includes(first)) return 'weekdays';
  if (['theo','teo'].includes(first)) return 'apprentice';
  if (first === 'babette') return 'tue_sat';
  if (['jessica','nina','kilian','luise'].includes(first)) return 'casual';
  return 'unassigned';
}
export function plannedStatus(profile, date, override = null) {
  if (override && ['off','school','work'].includes(override)) return override;
  const day = new Date(`${date}T12:00:00Z`).getUTCDay();
  if (profile === 'casual') return 'flexible';
  if (!profiles[profile] || profile === 'unassigned') return 'unassigned';
  if (profile === 'tue_sat') return day >= 2 && day <= 6 ? 'work' : 'off';
  if (day === 0 || day === 6) return 'off';
  if (profile === 'apprentice' && day === 3) {
    if (date < '2024-07-29' || date > '2030-09-09') return 'calendar_missing';
    return schoolHolidays.some(([from,to])=>date>=from && date<=to) ? 'work' : 'school';
  }
  return 'work';
}
export function countsSick(profile, date, status, override = null) {
  return status === 'sick' && profile !== 'casual' && plannedStatus(profile,date,override) === 'work';
}
export function duration(minutes) { return `${Math.floor(minutes/60)}h ${minutes%60}m`; }
export function monthRange(month) {
  if(typeof month!=='string' || !/^[1-9]\d{3}-(0[1-9]|1[0-2])$/.test(month) || !validDate(month+'-01')) throw new Error('Bitte einen gültigen Monat auswählen.');
  return {from:month+'-01',to:new Date(Date.UTC(+month.slice(0,4),+month.slice(5),0)).toISOString().slice(0,10)};
}
export function periodTotals(employee,entries,statuses,from,to) {
  const days=entries.filter(entry=>entry.employee_id===employee.id && entry.date>=from && entry.date<=to);
  return {minutes:days.filter(entry=>entry.check_out).reduce((sum,entry)=>sum+entry.netMinutes,0),open:days.filter(entry=>entry.check_in&&!entry.check_out).length,
    sick:statuses.filter(status=>status.employee_id===employee.id && status.date>=from && status.date<=to && countsSick(employee.schedule_profile,status.date,status.status,status.planned_override)).length};
}
export function summary(entry, breaks = [], now = new Date()) {
  if (!entry?.check_in) return {workMinutes:0,breakMinutes:0,netMinutes:0,pausesCount:0};
  const start = new Date(entry.check_in).getTime();
  const end = new Date(entry.check_out || now).getTime();
  const workMinutes = Math.max(0,Math.floor((end-start)/60000));
  let breakMinutes = breaks.reduce((sum,b)=>sum+(b.start ? Math.max(0, Math.floor((Math.min(new Date(b.end || end).getTime(),end)-Math.max(new Date(b.start).getTime(),start))/60000)) : 0),0);
  if (entry.break_minutes_override !== null && entry.break_minutes_override !== undefined) breakMinutes = Number(entry.break_minutes_override);
  return {workMinutes, breakMinutes, netMinutes:Math.max(0,workMinutes-breakMinutes), pausesCount:breaks.length};
}
