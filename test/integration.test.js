import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomInt } from 'node:crypto';
import { Pool } from 'pg';
import ExcelJS from 'exceljs';
import { dateKey, fromLocal, addDays } from '../public/js/rules.js';

const connectionString=process.env.TEST_DATABASE_URL;
test('migration, admin corrections, sickness and onsite booking against PostgreSQL',{skip:!connectionString,timeout:60000},async t=>{
  // This suite owns an empty, disposable database named exactly timely_test.
  assert.equal(new URL(connectionString).pathname,'/timely_test','Use a dedicated database named timely_test');
  const pool=new Pool({connectionString,ssl:false});
  const adminPin=String(randomInt(100000,1000000)),workerPin=String(randomInt(100000,1000000));
  let server,logs='';
  try {
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public');
    // Reproduce the old schema and verify that startup preserves its records.
    await pool.query(`CREATE TABLE employees(id SERIAL PRIMARY KEY,name TEXT NOT NULL UNIQUE,pin TEXT NOT NULL,is_admin BOOLEAN NOT NULL DEFAULT FALSE);
      CREATE TABLE time_entries(id SERIAL PRIMARY KEY,employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,date DATE NOT NULL,check_in TIMESTAMPTZ,check_out TIMESTAMPTZ);
      CREATE TABLE breaks(id SERIAL PRIMARY KEY,entry_id INTEGER NOT NULL REFERENCES time_entries(id) ON DELETE CASCADE,start TIMESTAMPTZ,"end" TIMESTAMPTZ);`);
    await pool.query('INSERT INTO employees(name,pin,is_admin) VALUES($1,$2,TRUE),($3,$4,FALSE),($5,$4,FALSE),($6,$4,FALSE),($7,$4,FALSE)', ['Test Admin',adminPin,'Sebastian',workerPin,'Babette','Theo','Jessica']);
    await pool.query("INSERT INTO time_entries(employee_id,date,check_in) VALUES(2,'2026-10-19','2026-10-19T05:00:00Z')");
    server=spawn(process.execPath,['server.js'],{cwd:new URL('../',import.meta.url),env:{...process.env,DATABASE_URL:connectionString,NODE_ENV:'test',PORT:'3107',HOST:'127.0.0.1',APP_URL:'http://127.0.0.1:3107',SESSION_SECRET:'test-session-secret-at-least-32-characters',TRUST_PROXY:'1'},windowsHide:true,stdio:['ignore','pipe','pipe']});
    server.stdout.on('data',chunk=>logs+=chunk);server.stderr.on('data',chunk=>logs+=chunk);
    let ready=false;
    for(let i=0;i<100;i++) {try {ready=(await fetch('http://127.0.0.1:3107/health')).ok;} catch{} if(ready) break; if(server.exitCode!==null) throw new Error(logs); await new Promise(resolve=>setTimeout(resolve,100));}
    assert.ok(ready,'Server should start');
    function browser(ip='203.0.113.10') {
      let cookie='';
      return async(url,body)=>{
        const headers={'x-forwarded-for':ip};if(cookie) headers.cookie=cookie;
        if(body) headers['content-type']='application/x-www-form-urlencoded';
        const response=await fetch('http://127.0.0.1:3107'+url,{method:body?'POST':'GET',redirect:'manual',headers,body:body?new URLSearchParams(body):undefined});
        const setCookie=response.headers.get('set-cookie');if(setCookie) cookie=setCookie.split(';')[0];
        return {status:response.status,location:response.headers.get('location'),body:Buffer.from(await response.arrayBuffer())};
      };
    }
    const csrf=response=>{const token=response.body.toString().match(/name="_csrf" value="([^"]+)"/);assert.ok(token,response.body.toString());return token[1];};
    async function login(request,id,pin) {const page=await request('/login');assert.equal((await request('/login',{_csrf:csrf(page),employee_id:id,pin})).status,302);}
    const admin=browser(); await login(admin,1,adminPin);
    const initialAdmin=await admin('/admin?week=2026-10-19');assert.equal(initialAdmin.status,200,logs);
    let token=csrf(initialAdmin);
    await t.test('migration preserves old records and assigns requested workdays',async()=>{
      assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM time_entries')).rows[0].n,1);
      assert.deepEqual((await pool.query('SELECT schedule_profile FROM employees ORDER BY id')).rows.map(e=>e.schedule_profile),['unassigned','weekdays','tue_sat','apprentice','casual']);
      assert.equal((await admin('/admin?week=2026-10-19')).status,200);
    });
    const correction={_csrf:token,employee_id:'2',date:'2026-10-19',id:'1',revision:'0',check_in:'2026-10-19T07:00',check_out:'2026-10-19T16:00',break_minutes:'30',reason:'Auschecken vergessen und Ende geklärt',week:'2026-10-19'};
    await t.test('admin closes forgotten checkout, validates order and rejects stale edits',async()=>{
      assert.equal((await admin('/admin/entries/save',{...correction,check_out:'2026-10-19T06:00'})).status,400);
      assert.equal((await admin('/admin/entries/save',correction)).status,302);
      const entry=(await pool.query('SELECT * FROM time_entries WHERE id=1')).rows[0];
      assert.equal(entry.check_out.toISOString(),'2026-10-19T14:00:00.000Z');assert.equal(entry.break_minutes_override,30);
      assert.equal((await admin('/admin/entries/save',correction)).status,409);
      assert.equal((await pool.query("SELECT COUNT(*)::int AS n FROM audit_log WHERE kind='Zeitkorrektur'")).rows[0].n,1);
      assert.equal((await admin('/admin/entries/edit?employee_id=2&date=2026-10-19&id=1')).status,200);
    });
    await t.test('non-admin access and CSRF fail before any change',async()=>{
      assert.equal((await admin('/admin/days/save',{employee_id:'2'})).status,403);
      const worker=browser();await login(worker,2,workerPin);
      assert.equal((await worker('/admin')).status,403);
      const employeeToken=csrf(await worker('/'));
      assert.equal((await worker('/admin/entries/save',{...correction,_csrf:employeeToken,revision:'1'})).status,403);
    });
    await t.test('sickness across a week follows each employee schedule, including holidays',async()=>{
      for(const employee_id of ['3','4','5']) assert.equal((await admin('/admin/days/save',{_csrf:token,employee_id,from:'2026-10-19',to:'2026-10-25',status:'sick',reason:'Krankmeldung Test',week:'2026-10-19'})).status,302);
      const response=await admin('/admin/export?from=2026-10-19&to=2026-10-25');assert.equal(response.status,200);
      const workbook=new ExcelJS.Workbook();await workbook.xlsx.load(response.body);
      const rows=workbook.getWorksheet('Wochen').getSheetValues().slice(2);
      assert.equal(rows.find(r=>r?.[2]==='Babette')[4],5);
      assert.equal(rows.find(r=>r?.[2]==='Theo')[4],4);
      assert.equal(rows.find(r=>r?.[2]==='Jessica')[4],0);
      assert.equal((await admin('/admin/days/save',{_csrf:token,employee_id:'4',from:'2026-11-02',to:'2026-11-06',status:'sick',reason:'Ferienwoche Test',week:'2026-11-02'})).status,302);
      const holidayExport=await admin('/admin/export?from=2026-11-02&to=2026-11-06');
      await workbook.xlsx.load(holidayExport.body);assert.equal(workbook.getWorksheet('Wochen').getRow(2).getCell(4).value,5);
    });
    await t.test('absence ranges roll back completely on conflict; export does not mutate times',async()=>{
      const before=JSON.stringify((await pool.query('SELECT * FROM time_entries ORDER BY id')).rows);
      assert.equal((await admin('/admin/days/save',{_csrf:token,employee_id:'2',from:'2026-10-18',to:'2026-10-20',status:'sick',reason:'Konflikt prüfen'})).status,400);
      assert.equal((await pool.query('SELECT * FROM day_statuses WHERE employee_id=2')).rows.length,0);
      assert.equal((await admin('/admin/export?from=2026-10-19&to=2026-10-25')).status,200);
      assert.equal(JSON.stringify((await pool.query('SELECT * FROM time_entries ORDER BY id')).rows),before);
      assert.equal((await pool.query('SELECT * FROM breaks')).rows.length,0);
    });
    await t.test('printed QR requires allowed network and a fresh one-use scan on every action',async()=>{
      assert.equal((await admin('/admin/onsite',{_csrf:token,enabled:'on',networks:'203.0.113.10',reason:'Betriebsnetz einrichten'})).status,302);
      const qr=(await pool.query("SELECT value FROM app_settings WHERE key='onsite'")).rows[0].value.token;
      const remote=browser('198.51.100.20');await login(remote,2,workerPin);
      assert.equal((await remote('/vor-ort/'+qr)).status,403);
      const remoteToken=csrf(await remote('/'));
      assert.equal((await remote('/action/checkin',{_csrf:remoteToken})).status,403);
      const local=browser();await login(local,2,workerPin);
      let localToken=csrf(await local('/'));
      assert.equal((await local('/action/checkin',{_csrf:localToken})).status,403);
      await local('/vor-ort/'+qr);
      await pool.query("UPDATE onsite_grants SET expires=NOW()-INTERVAL '1 second'");
      assert.equal((await local('/action/checkin',{_csrf:localToken})).status,403);
      assert.equal((await local('/vor-ort/'+qr)).status,302);
      assert.equal((await local('/action/checkin',{_csrf:localToken})).status,302);
      assert.equal((await local('/action/checkout',{_csrf:localToken})).status,403);
      await local('/vor-ort/'+qr);
      // Replaying a single scan concurrently can commit only one booking.
      const race=await Promise.all([local('/action/break-start',{_csrf:localToken}),local('/action/checkout',{_csrf:localToken})]);
      assert.equal(race.filter(r=>r.status===302).length,1);assert.equal(race.filter(r=>r.status===403).length,1);
      const today=(await pool.query('SELECT id,check_out FROM time_entries WHERE employee_id=2 AND date=$1',[dateKey()])).rows[0];
      if(!today.check_out) {await local('/vor-ort/'+qr);assert.equal((await local('/action/checkout',{_csrf:localToken})).status,302);}
      const scanBeforeLogin=browser();
      assert.equal((await scanBeforeLogin('/vor-ort/'+qr)).status,302);
      await login(scanBeforeLogin,5,workerPin);
      // Remove the fixture's sickness for today, then book using the scan preserved through login.
      await pool.query('DELETE FROM day_statuses WHERE employee_id=5 AND date=$1',[dateKey()]);
      const freshToken=csrf(await scanBeforeLogin('/'));
      assert.equal((await scanBeforeLogin('/action/checkin',{_csrf:freshToken})).status,302);
      assert.equal((await scanBeforeLogin('/action/checkout',{_csrf:freshToken})).status,403);
      await local('/vor-ort/'+qr);
      assert.equal((await admin('/admin/onsite',{_csrf:token,enabled:'on',networks:'203.0.113.10',rotate:'on',reason:'Ausdruck ersetzen'})).status,302);
      assert.equal((await local('/vor-ort/'+qr)).status,403);
      assert.equal((await local('/action/break-start',{_csrf:localToken})).status,403);
    });
    await t.test('deactivation preserves records and revokes the active user session',async()=>{
      const worker=browser();await login(worker,3,workerPin);
      assert.equal((await admin('/admin/employees/deactivate',{_csrf:token,id:'3',reason:'Austritt Test'})).status,302);
      assert.equal((await worker('/')).location,'/login');
      assert.ok((await pool.query('SELECT * FROM day_statuses WHERE employee_id=3')).rows.length);
    });
    assert.ok(!logs.includes('Timely request failed:'),logs);
  } finally {if(server&&server.exitCode===null) {server.kill();await new Promise(resolve=>server.once('exit',resolve));} await pool.end();}
});
