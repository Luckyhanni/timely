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
      const cookies=new Map();
      const request=async(url,body)=>{
        const headers={'x-forwarded-for':ip};if(cookies.size) headers.cookie=[...cookies].map(([name,value])=>`${name}=${value}`).join('; ');
        if(body) headers['content-type']='application/x-www-form-urlencoded';
        const response=await fetch('http://127.0.0.1:3107'+url,{method:body?'POST':'GET',redirect:'manual',headers,body:body?new URLSearchParams(body):undefined});
        const setCookies=response.headers.getSetCookie();
        for(const line of setCookies) {
          const pair=line.split(';')[0],split=pair.indexOf('='),name=pair.slice(0,split),value=pair.slice(split+1);
          if(!value || /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(line)) cookies.delete(name);else cookies.set(name,value);
        }
        return {status:response.status,location:response.headers.get('location'),body:Buffer.from(await response.arrayBuffer()),setCookies};
      };
      request.cookies=cookies;request.setIp=value=>{ip=value;};request.dropSession=()=>cookies.delete('connect.sid');
      return request;
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
      assert.equal((await worker('/admin/network-info')).status,403);
      const networkInfo=await admin('/admin/network-info');assert.equal(networkInfo.status,200);
      assert.deepEqual(JSON.parse(networkInfo.body.toString()),{clientIp:'203.0.113.10',socketAddress:'127.0.0.1',forwardedFor:['203.0.113.10'],trustedProxyCount:1});
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
      assert.deepEqual(JSON.parse((await remote('/network-status')).body.toString()),{required:true,atWork:false});
      assert.deepEqual(JSON.parse((await browser()('/network-status')).body.toString()),{required:true,atWork:true});
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
    await t.test('remembered personal devices require a PIN once and retain all onsite protections',async t=>{
      const employee=(await pool.query("INSERT INTO employees(name,pin,schedule_profile) VALUES('QR Testperson',$1,'casual') RETURNING id",[workerPin])).rows[0];
      const employeeId=employee.id;
      let qr=(await pool.query("SELECT value FROM app_settings WHERE key='onsite'")).rows[0].value.token;
      async function pair(request,id=employeeId,pin=workerPin,label='Test-Handy') {
        assert.equal((await request('/vor-ort/'+qr)).location,'/login');
        const page=await request('/login');
        return request('/login',{_csrf:csrf(page),employee_id:String(id),pin,remember_device:'on',device_label:label});
      }
      async function deviceFor(request) {
        const {createHash}=await import('node:crypto');
        const hash=createHash('sha256').update(request.cookies.get('timely_device')).digest('hex');
        return (await pool.query('SELECT * FROM remembered_devices WHERE token_hash=$1',[hash])).rows[0];
      }
      const phone=browser();
      await t.test('first scan asks for identity; wrong PIN creates no remembered device',async()=>{
        assert.equal((await phone('/vor-ort/'+qr)).location,'/login');
        const page=await phone('/login');assert.match(page.body.toString(),/Handy einmalig anmelden/);
        assert.equal((await phone('/login',{_csrf:csrf(page),employee_id:String(employeeId),pin:'000000',remember_device:'on'})).status,401);
        assert.equal(phone.cookies.has('timely_device'),false);
        assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM remembered_devices')).rows[0].n,0);
      });
      await t.test('valid on-site PIN links one device and stores only a token hash',async()=>{
        const response=await pair(phone);assert.equal(response.status,302);
        const cookie=response.setCookies.find(c=>c.startsWith('timely_device='));
        assert.match(cookie,/HttpOnly/);assert.match(cookie,/SameSite=Lax/);assert.match(cookie,/Path=\//);assert.match(cookie,/Max-Age=31536000/);assert.doesNotMatch(cookie,/Domain=/);
        const device=await deviceFor(phone);assert.equal(device.employee_id,employeeId);assert.equal(device.label,'Test-Handy');
        assert.notEqual(device.token_hash,phone.cookies.get('timely_device'));assert.equal(device.token_hash.length,64);
        const page=await phone('/');assert.match(page.body.toString(),/QR Testperson/);assert.match(page.body.toString(),/Dieses Handy ist mit deinem Konto verknüpft/);
        assert.equal((await phone('/action/checkin',{_csrf:csrf(page)})).status,302);
        assert.equal((await phone('/action/checkout',{_csrf:csrf(page)})).status,403,'one scan still permits one action only');
      });
      await t.test('after session loss a QR scan restores the correct user without a PIN and renews the device',async()=>{
        const device=await deviceFor(phone),oldToken=phone.cookies.get('timely_device');
        await pool.query("UPDATE remembered_devices SET expires_at=NOW()+INTERVAL '1 day' WHERE id=$1",[device.id]);
        phone.dropSession();assert.equal((await phone('/')).location,'/login','device cookie alone must not restore a session');
        assert.equal((await phone('/vor-ort/'+qr)).location,'/');
        assert.match((await phone('/')).body.toString(),/QR Testperson/);
        assert.equal(phone.cookies.get('timely_device'),oldToken);
        assert.ok((await deviceFor(phone)).expires_at>Date.now()+300*86400000);
        assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM remembered_devices WHERE employee_id=$1',[employeeId])).rows[0].n,1);
        assert.equal((await phone('/action/break-start',{_csrf:csrf(await phone('/login'))})).status,302);
      });
      await t.test('new browsers need a PIN and an expired scan cannot link a device',async()=>{
        const fresh=browser();assert.equal((await fresh('/vor-ort/'+qr)).location,'/login');
        const page=await fresh('/login');await pool.query("UPDATE onsite_grants SET expires=NOW()-INTERVAL '1 second'");
        assert.equal((await fresh('/login',{_csrf:csrf(page),employee_id:String(employeeId),pin:workerPin,remember_device:'on'})).status,403);
        assert.equal(fresh.cookies.has('timely_device'),false);
        const direct=browser(),directPage=await direct('/login');
        assert.equal((await direct('/login',{_csrf:csrf(directPage),employee_id:String(employeeId),pin:workerPin,remember_device:'on'})).status,403,'PIN alone cannot link a device');
      });
      await t.test('outside the allowed network a known phone cannot restore or continue a device session',async()=>{
        assert.equal((await phone('/vor-ort/'+qr)).location,'/');
        phone.setIp('198.51.100.20');
        assert.equal((await phone('/vor-ort/'+qr)).status,403);
        assert.equal((await phone('/history')).location,'/login');
        assert.equal((await phone('/action/checkout',{_csrf:csrf(await phone('/login'))})).location,'/login');
        phone.setIp('203.0.113.10');assert.equal((await phone('/vor-ort/'+qr)).location,'/');
      });
      await t.test('one browser cannot silently switch its remembered employee',async()=>{
        const page=await phone('/login'),before=phone.cookies.get('timely_device');
        assert.equal((await phone('/login',{_csrf:csrf(page),employee_id:'2',pin:workerPin,remember_device:'on'})).status,409);
        assert.equal(phone.cookies.get('timely_device'),before);assert.equal((await deviceFor(phone)).employee_id,employeeId);
      });
      await t.test('QR rotation invalidates old scans while a new QR still recognises the linked phone',async()=>{
        await phone('/vor-ort/'+qr);
        assert.equal((await admin('/admin/onsite',{_csrf:token,enabled:'on',networks:'203.0.113.10\n2001:db8:1234::/64',rotate:'on',reason:'QR bei Geräteprüfung ersetzen'})).status,302);
        assert.equal((await phone('/vor-ort/'+qr)).status,403);
        assert.equal((await phone('/action/break-end',{_csrf:csrf(await phone('/login'))})).status,403);
        qr=(await pool.query("SELECT value FROM app_settings WHERE key='onsite'")).rows[0].value.token;
        phone.dropSession();assert.equal((await phone('/vor-ort/'+qr)).location,'/');
        assert.equal((await phone('/action/break-end',{_csrf:csrf(await phone('/login'))})).status,302);
      });
      await t.test('allowed IPv6 works and a different IPv6 network is rejected',async()=>{
        phone.dropSession();phone.setIp('2001:db8:1234::42');assert.equal((await phone('/vor-ort/'+qr)).location,'/');
        assert.match((await phone('/')).body.toString(),/QR Testperson/);
        assert.equal((await phone('/action/checkout',{_csrf:csrf(await phone('/login'))})).status,302);
        phone.setIp('2001:db8:4321::42');assert.equal((await phone('/vor-ort/'+qr)).status,403);
        phone.setIp('203.0.113.10');
      });
      await t.test('admin can revoke a lost device and the old cookie and session stop working',async()=>{
        await phone('/vor-ort/'+qr);const device=await deviceFor(phone);
        assert.match((await admin('/admin')).body.toString(),/Test-Handy/);
        assert.equal((await admin('/admin/devices/revoke',{_csrf:token,id:device.id,reason:'Test: Handy verloren'})).status,302);
        assert.equal((await phone('/history')).location,'/login');
        assert.equal((await phone('/vor-ort/'+qr)).location,'/login');assert.equal(phone.cookies.has('timely_device'),false);
        assert.ok((await pool.query('SELECT revoked_at FROM remembered_devices WHERE id=$1',[device.id])).rows[0].revoked_at);
      });
      await t.test('a user can forget their own phone and must use a PIN again',async()=>{
        assert.equal((await pair(phone)).status,302);const device=await deviceFor(phone);
        const page=await phone('/devices');assert.match(page.body.toString(),/Dieses Gerät/);
        assert.equal((await phone('/devices/revoke',{_csrf:csrf(page),id:device.id})).location,'/login');
        assert.equal(phone.cookies.has('timely_device'),false);assert.equal((await phone('/vor-ort/'+qr)).location,'/login');
      });
      await t.test('other employees cannot revoke someone else\'s remembered phone; CSRF is enforced',async()=>{
        assert.equal((await pair(phone)).status,302);const device=await deviceFor(phone),other=browser();
        await login(other,2,workerPin);
        assert.equal((await other('/devices/revoke',{id:device.id})).status,403);
        assert.equal((await other('/devices/revoke',{_csrf:csrf(await other('/login')),id:device.id})).status,404);
        assert.equal((await other('/admin/devices/revoke',{_csrf:csrf(await other('/login')),id:device.id,reason:'Unberechtigter Versuch'})).status,403);
        assert.equal((await deviceFor(phone)).revoked_at,null);
      });
      await t.test('expired device requires a PIN; a shared device can opt out of linking',async()=>{
        const device=await deviceFor(phone);await pool.query("UPDATE remembered_devices SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",[device.id]);
        assert.equal((await phone('/vor-ort/'+qr)).location,'/login');assert.equal(phone.cookies.has('timely_device'),false);
        const shared=browser();await shared('/vor-ort/'+qr);await login(shared,employeeId,workerPin);
        assert.equal(shared.cookies.has('timely_device'),false);
      });
      await t.test('changing the PIN revokes all devices and existing sessions of that employee',async()=>{
        assert.equal((await pair(phone)).status,302);const plain=browser();await login(plain,employeeId,workerPin);
        const newPin=String(randomInt(100000,1000000));
        assert.equal((await admin('/admin/employees/update',{_csrf:token,id:String(employeeId),name:'QR Testperson',pin:newPin,schedule_profile:'casual',active:'on',reason:'Test: PIN geändert'})).status,302);
        assert.equal((await phone('/history')).location,'/login');assert.equal((await plain('/history')).location,'/login');
        assert.equal((await phone('/vor-ort/'+qr)).location,'/login');
        assert.equal((await pair(phone,employeeId,newPin)).status,302);
      });
      await t.test('device-based admin login requires a fresh PIN before any admin access',async()=>{
        const adminPhone=browser();assert.equal((await pair(adminPhone,1,adminPin,'Admin-Testgerät')).status,302);
        await adminPhone('/logout');assert.ok(adminPhone.cookies.has('timely_device'));
        assert.equal((await adminPhone('/vor-ort/'+qr)).location,'/');
        assert.equal((await adminPhone('/admin')).location,'/login?admin=1');
        const page=await adminPhone('/login?admin=1');assert.match(page.body.toString(),/Verwaltung freischalten/);
        assert.equal((await adminPhone('/admin/devices/revoke',{_csrf:csrf(page),id:(await deviceFor(phone)).id,reason:'Keine PIN'})).status,403);
        assert.equal((await adminPhone('/login',{_csrf:csrf(page),employee_id:'1',pin:adminPin,admin_login:'1'})).location,'/admin');
        assert.equal((await adminPhone('/admin')).status,200);
      });
      await t.test('disabled employees lose the pairing and cannot scan back into their accounts',async()=>{
        assert.equal((await admin('/admin/employees/deactivate',{_csrf:token,id:String(employeeId),reason:'Test: Konto deaktiviert'})).status,302);
        assert.equal((await phone('/history')).location,'/login');assert.equal((await phone('/vor-ort/'+qr)).location,'/login');
        assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM remembered_devices WHERE employee_id=$1 AND revoked_at IS NULL',[employeeId])).rows[0].n,0);
      });
      assert.ok((await pool.query("SELECT id FROM audit_log WHERE kind='Gerät verknüpft'")).rows.length);
      assert.ok((await pool.query("SELECT id FROM audit_log WHERE kind='Gerät gesperrt'")).rows.length);
    });
    await t.test('deactivation preserves records and revokes the active user session',async()=>{
      const worker=browser();await login(worker,3,workerPin);
      assert.equal((await admin('/admin/employees/deactivate',{_csrf:token,id:'3',reason:'Austritt Test'})).status,302);
      assert.equal((await worker('/')).location,'/login');
      assert.ok((await pool.query('SELECT * FROM day_statuses WHERE employee_id=3')).rows.length);
    });
    await t.test('production behind TLS proxy issues host-only secure device cookies and restores on-site sessions',async()=>{
      const productionServer=spawn(process.execPath,['server.js'],{cwd:new URL('../',import.meta.url),env:{...process.env,DATABASE_URL:connectionString,NODE_ENV:'production',PORT:'3109',HOST:'127.0.0.1',APP_URL:'https://timely.example',SESSION_SECRET:'test-production-session-secret-at-least-32-characters',TRUST_PROXY:'2'},windowsHide:true,stdio:['ignore','pipe','pipe']});
      let productionLogs='';productionServer.stdout.on('data',chunk=>productionLogs+=chunk);productionServer.stderr.on('data',chunk=>productionLogs+=chunk);
      try {
        let ready=false;
        for(let i=0;i<100;i++) {try {ready=(await fetch('http://127.0.0.1:3109/health')).ok;} catch{} if(ready) break;if(productionServer.exitCode!==null) throw new Error(productionLogs);await new Promise(resolve=>setTimeout(resolve,100));}
        assert.ok(ready,'Production server should start against the already migrated schema');
        const cookies=new Map();
        const request=async(url,body)=>{
          const response=await fetch('http://127.0.0.1:3109'+url,{method:body?'POST':'GET',redirect:'manual',headers:{'x-forwarded-for':'198.51.100.20, 203.0.113.10, 10.30.208.245','x-forwarded-proto':'https',cookie:[...cookies].map(([key,value])=>`${key}=${value}`).join('; '),...(body?{'content-type':'application/x-www-form-urlencoded'}:{})},body:body?new URLSearchParams(body):undefined});
          const setCookies=response.headers.getSetCookie();for(const line of setCookies) {const pair=line.split(';')[0],split=pair.indexOf('=');cookies.set(pair.slice(0,split),pair.slice(split+1));}
          return {status:response.status,location:response.headers.get('location'),body:Buffer.from(await response.arrayBuffer()),setCookies};
        };
        const qr=(await pool.query("SELECT value FROM app_settings WHERE key='onsite'")).rows[0].value.token;
        assert.deepEqual(JSON.parse((await request('/network-status')).body.toString()),{required:true,atWork:true},'a client-supplied prefix must not override the IP appended by the trusted proxies');
        await request('/vor-ort/'+qr);const page=await request('/login');
        const paired=await request('/login',{_csrf:csrf(page),employee_id:'2',pin:workerPin,remember_device:'on',device_label:'Produktionsmodus-Test'});
        assert.equal(paired.status,302);
        const deviceCookie=paired.setCookies.find(value=>value.startsWith('__Host-timely_device='));assert.ok(deviceCookie);
        for(const attribute of ['Secure','HttpOnly','SameSite=Lax','Path=/','Max-Age=31536000']) assert.ok(deviceCookie.includes(attribute),attribute);
        assert.doesNotMatch(deviceCookie,/Domain=/);
        assert.ok(paired.setCookies.find(value=>value.startsWith('connect.sid=')&&value.includes('Secure')));
        cookies.delete('connect.sid');assert.equal((await request('/')).location,'/login');
        assert.equal((await request('/vor-ort/'+qr)).location,'/');assert.match((await request('/')).body.toString(),/Sebastian/);
        assert.ok(!productionLogs.includes('Timely request failed:'),productionLogs);
      } finally {if(productionServer.exitCode===null) {productionServer.kill();await new Promise(resolve=>productionServer.once('exit',resolve));}}
    });
    assert.ok(!logs.includes('Timely request failed:'),logs);
  } finally {if(server&&server.exitCode===null) {server.kill();await new Promise(resolve=>server.once('exit',resolve));} await pool.end();}
});
