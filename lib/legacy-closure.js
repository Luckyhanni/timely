import { createHash } from 'node:crypto';
import { dateKey,addDays } from '../public/js/rules.js';

// This is an explicit, previewed admin operation, never a startup migration.
export async function closurePlan(db,cutoff,now=new Date()) {
  const entries=(await db.query(`SELECT t.*,e.name FROM time_entries t JOIN employees e ON e.id=t.employee_id
    WHERE t.check_in IS NOT NULL AND t.check_out IS NULL AND t.date<=$1
    ORDER BY t.employee_id,t.check_in,t.id`,[cutoff])).rows.filter(entry=>dateKey(entry.check_in)<=cutoff);
  if(entries.length>1000) {const error=new Error('Bitte höchstens 1000 Buchungen auf einmal bearbeiten.');error.status=400;throw error;}
  const employeeIds=[...new Set(entries.map(entry=>entry.employee_id))].sort((a,b)=>a-b);
  const [all,pauses]=entries.length ? await Promise.all([
    db.query('SELECT * FROM time_entries WHERE employee_id=ANY($1::int[]) ORDER BY id',[employeeIds]),
    db.query('SELECT * FROM breaks WHERE entry_id=ANY($1::int[]) ORDER BY id',[entries.map(entry=>entry.id)])
  ]) : [{rows:[]},{rows:[]}];
  const ends=new Map(entries.map(entry=>[entry.id,new Date(new Date(entry.check_in).getTime()+510*60000)]));
  const rows=entries.map(entry=>{
    const start=new Date(entry.check_in),end=ends.get(entry.id),date=dateKey(start);
    const overlaps=all.rows.filter(other=>other.id!==entry.id && other.employee_id===entry.employee_id && other.check_in
      && new Date(other.check_in)<end && (other.check_out?new Date(other.check_out):(ends.get(other.id)||Infinity))>start);
    const issues=[];
    if(end>now) issues.push('Das berechnete Ende liegt noch in der Zukunft.');
    if(overlaps.length) issues.push('Überschneidung mit einer anderen Buchung.');
    const followingDay=dateKey(end)!==date;
    if(followingDay && dateKey(end)!==addDays(date,1)) issues.push('Ungültige Tagesgrenze.');
    return {entry,start,end,date,followingDay,breaks:pauses.rows.filter(p=>p.entry_id===entry.id),issues};
  });
  const fingerprint=createHash('sha256').update(JSON.stringify({cutoff,rows:rows.map(row=>({entry:row.entry,breaks:row.breaks,end:row.end,issues:row.issues}))})).digest('hex');
  return {rows,employeeIds,fingerprint,blocked:rows.some(row=>row.issues.length)};
}
