import test from 'node:test';
import assert from 'node:assert/strict';
import {defaultProfile,plannedStatus,countsSick,validDate,monday,weekNumber,dateKey,fromLocal,localDateTime,summary} from '../public/js/rules.js';
import {parseNetworks,validGrant} from '../lib/onsite.js';

test('the requested employees receive their work profiles',()=>{
  for(const name of ['Sebastian','Andi','David']) assert.equal(defaultProfile(name),'weekdays');
  assert.equal(defaultProfile('Theo Blank'),'apprentice'); assert.equal(defaultProfile('Babette'),'tue_sat');
  for(const name of ['Jessica','Nina','Kilian','Luise']) assert.equal(defaultProfile(name),'casual');
  assert.equal(defaultProfile('Unbekannt'),'unassigned');
});
test('fixed working days and Saturday for Babette',()=>{
  const dates=['2026-10-19','2026-10-20','2026-10-21','2026-10-22','2026-10-23','2026-10-24','2026-10-25'];
  assert.deepEqual(dates.map(d=>plannedStatus('weekdays',d)),['work','work','work','work','work','off','off']);
  assert.deepEqual(dates.map(d=>plannedStatus('tue_sat',d)),['off','work','work','work','work','work','off']);
});
test('Wednesday school, Bavaria holidays and an explicit school exception',()=>{
  assert.equal(plannedStatus('apprentice','2026-10-21'),'school');
  for(const date of ['2026-08-05','2026-11-04','2026-12-30','2027-02-10','2027-03-24','2027-05-19']) assert.equal(plannedStatus('apprentice',date),'work');
  assert.equal(plannedStatus('apprentice','2026-10-21','work'),'work');
  assert.equal(plannedStatus('apprentice','2031-01-15'),'calendar_missing');
});
test('only recorded sickness on planned onsite days counts, never casuals',()=>{
  assert.equal(countsSick('weekdays','2026-10-19',null),false);
  assert.equal(countsSick('weekdays','2026-10-19','sick'),true);
  assert.equal(countsSick('weekdays','2026-10-24','sick'),false);
  assert.equal(countsSick('tue_sat','2026-10-24','sick'),true);
  assert.equal(countsSick('apprentice','2026-10-21','sick'),false);
  assert.equal(countsSick('apprentice','2026-11-04','sick'),true);
  assert.equal(countsSick('casual','2026-10-19','sick','work'),false);
  assert.equal(countsSick('weekdays','2026-10-19','sick','off'),false);
});
test('calendar weeks, year boundary and Berlin midnight',()=>{
  assert.equal(monday('2026-10-25'),'2026-10-19');
  assert.equal(monday('2027-01-01'),'2026-12-28');
  assert.equal(weekNumber('2027-01-01'),'2026 · KW 53');
  assert.equal(dateKey('2026-10-21T22:30:00Z'),'2026-10-22');
  assert.equal(validDate('2026-02-30'),false);assert.equal(validDate('2024-02-29'),true);
});
test('local correction timestamps do not depend on server zone, including DST',()=>{
  assert.equal(fromLocal('2026-10-20T07:00'),'2026-10-20T05:00:00.000Z');
  assert.equal(fromLocal('2026-12-20T07:00'),'2026-12-20T06:00:00.000Z');
  assert.equal(localDateTime(fromLocal('2026-10-25T02:30')),'2026-10-25T02:30');
  assert.throws(()=>fromLocal('2026-03-29T02:30'));
  assert.throws(()=>fromLocal('2026-10-20T25:00'));
});
test('pauses stop at check-out and a corrected total overrides recorded pauses',()=>{
  const entry={check_in:'2026-10-20T06:00Z',check_out:'2026-10-20T14:00Z'};
  const pauses=[{start:'2026-10-20T10:00Z',end:'2026-10-20T10:30Z'}];
  assert.equal(summary(entry,pauses).netMinutes,450);
  assert.equal(summary({...entry,break_minutes_override:45},pauses).netMinutes,435);
  assert.equal(summary(entry,[{start:'2026-10-20T13:30Z',end:null}],new Date('2026-10-22')).breakMinutes,30);
});
test('onsite networks normalize mapped IPv4, support IPv6 and reject invalid networks',()=>{
  const list=parseNetworks('203.0.113.10\n2001:db8:abcd::/64');
  assert.equal(list.contains('::ffff:203.0.113.10'),true);
  assert.equal(list.contains('203.0.113.11'),false);
  assert.equal(list.contains('2001:db8:abcd::12'),true);
  assert.equal(list.contains('2001:db8:ffff::12'),false);
  for(const value of ['0.0.0.0/0','203.0.113.10/33','anything']) assert.throws(()=>parseNetworks(value));
  assert.equal(parseNetworks('').contains('127.0.0.1'),false);
});
test('scan expires and is invalidated when the printed code changes',()=>{
  assert.equal(validGrant({token:'a',expires:2000},'a',1000),true);
  assert.equal(validGrant({token:'a',expires:2000},'a',2000),false);
  assert.equal(validGrant({token:'a',expires:2000},'b',1000),false);
});
