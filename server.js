import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import morgan from 'morgan';
import helmet from 'helmet';
import { Pool, types } from 'pg';
import ExcelJS from 'exceljs';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc.js';
import timezone from 'dayjs/plugin/timezone.js';
import ejsMate from 'ejs-mate';
import QRCode from 'qrcode';
import { ensureSchema } from './lib/schema.js';
import { parseNetworks, validGrant, newQrToken, normalizeIp } from './lib/onsite.js';
import { deviceLifetime,deviceCookieName,deviceCookieOptions,deviceToken,tokenHash,newDevice,deviceLabel,findDevice,listDevices } from './lib/devices.js';
import { TZ, profiles, statusLabels, validDate, dateKey, addDays, monday, weekNumber, defaultProfile, plannedStatus, countsSick, duration, summary, fromLocal } from './public/js/rules.js';

dayjs.extend(utc); dayjs.extend(timezone);
types.setTypeParser(1082,value=>value);
const root = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const DEMO_MODE = process.env.TIMELY_DEMO === 'true' || !process.env.DATABASE_URL;
const production = process.env.NODE_ENV === 'production';
if (!DEMO_MODE && production && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) throw new Error('SESSION_SECRET mit mindestens 32 Zeichen erforderlich.');
const pool = DEMO_MODE ? null : new Pool({ connectionString:process.env.DATABASE_URL, ssl:process.env.DATABASE_URL.includes('sslmode=disable') ? false : {rejectUnauthorized:false} });
if (pool) await ensureSchema(pool);
// Configure only the known number of trusted reverse proxies.
if (process.env.TRUST_PROXY) {
  if (!/^[1-9]\d?$/.test(process.env.TRUST_PROXY)) throw new Error('TRUST_PROXY muss die Anzahl vertrauenswürdiger Proxys sein.');
  app.set('trust proxy',Number(process.env.TRUST_PROXY));
}
app.use(helmet({contentSecurityPolicy:false,referrerPolicy:{policy:'no-referrer'}}));
app.use(morgan(':method :url :status :response-time ms', {skip:req=>req.path.startsWith('/vor-ort/')}));
app.use(express.urlencoded({extended:false,limit:'32kb'}));
app.use(express.static(path.join(root,'public')));
app.engine('ejs',ejsMate); app.set('view engine','ejs'); app.set('views',path.join(root,'views'));
const PgSession = connectPgSimple(session);
app.use(session({secret:process.env.SESSION_SECRET || randomBytes(32).toString('hex'),resave:false,saveUninitialized:false,
  ...(pool ? {store:new PgSession({pool,createTableIfMissing:true})} : {}),
  cookie:{maxAge:12*60*60*1000,httpOnly:true,sameSite:'lax',secure:production}
}));
if (DEMO_MODE) app.use((req,res,next)=>req.path==='/health' ? next() : res.redirect('/demo.html'));
const route = handler => (req,res,next)=>Promise.resolve(handler(req,res,next)).catch(next);
function fail(message,status=400) { const error=new Error(message); error.status=status; throw error; }
function integer(value) { if(!/^\d+$/.test(String(value)) || +value<1 || !Number.isSafeInteger(+value)) fail('Ungültige Auswahl.'); return +value; }
function reason(value) { const text=String(value || '').trim(); if(text.length<3 || text.length>500) fail('Bitte einen Grund mit 3–500 Zeichen eingeben.'); return text; }
function checkDate(value) { if(!validDate(value)) fail('Bitte ein gültiges Datum wählen.'); return value; }
function sameSecret(a,b) { return typeof a==='string' && typeof b==='string' && Buffer.byteLength(a)===Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a),Buffer.from(b)); }
function clearDeviceCookie(res) {
  const {maxAge,...options}=deviceCookieOptions(production);
  res.clearCookie(deviceCookieName(production),options);
}
async function onsiteSettings(db=pool) { return (await db.query("SELECT value FROM app_settings WHERE key='onsite'")).rows[0].value; }
function baseUrl() {
  try { const url=new URL(process.env.APP_URL || 'https://blank-timely.de'); if(url.pathname!=='/' || url.search || url.hash || url.username || url.password || (url.protocol!=='https:' && !(url.protocol==='http:' && !production))) return null; return url.origin; } catch { return null; }
}
app.use(route(async(req,res,next)=>{
  res.set('Cache-Control','no-store');
  req.session.csrf ||= randomBytes(24).toString('hex');
  res.locals.csrf=req.session.csrf; res.locals.user=null; res.locals.deviceLinked=false; res.locals.flash=req.session.flash || null;
  delete req.session.flash;
  res.locals.duration=duration; res.locals.dayjs=dayjs; res.locals.TZ=TZ;
  if(req.method==='POST' && !sameSecret(req.body._csrf,req.session.csrf)) fail('Die Sitzung ist abgelaufen. Seite neu laden und erneut versuchen.',403);
  if(req.session.user) {
    const {rows}=await pool.query('SELECT id,name,is_admin,schedule_profile,auth_version FROM employees WHERE id=$1 AND active=TRUE',[req.session.user.id]);
    const employee=rows[0];
    let valid=employee && employee.auth_version===(req.session.authVersion ?? 0);
    if(valid && req.session.deviceId) {
      const device=await findDevice(pool,deviceToken(req,production));
      valid=device?.id===req.session.deviceId && device.employee_id===employee.id;
    }
    if(valid && req.session.authMethod==='device') {
      const settings=await onsiteSettings();
      valid=settings.enabled && parseNetworks(settings.networks).contains(req.ip);
    }
    if(!valid) { delete req.session.user; delete req.session.onsite; delete req.session.deviceId; delete req.session.authMethod; delete req.session.authVersion; }
    else { req.session.user=employee; res.locals.user=employee; res.locals.deviceLinked=!!req.session.deviceId; }
  }
  next();
}));
function auth(req,res,next) { if(!req.session.user) return res.redirect('/login'); next(); }
function admin(req,res,next) {
  if(!req.session.user?.is_admin) return res.status(403).render('error',{message:'Nur für Administratoren.'});
  if(req.session.authMethod==='device') {
    if(req.method==='GET') return res.redirect('/login?admin=1');
    return res.status(403).render('error',{message:'Für die Verwaltung bitte zuerst mit deiner PIN anmelden.'});
  }
  next();
}
async function audit(db,req,kind,employeeId,date,before,after,why) {
  await db.query('INSERT INTO audit_log(actor_id,actor_name,employee_id,kind,record_date,before_data,after_data,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[req.session.user.id,req.session.user.name,employeeId,kind,date,JSON.stringify(before),JSON.stringify(after),why]);
}
async function transaction(handler) {
  const db=await pool.connect();
  try { await db.query('BEGIN'); const result=await handler(db); await db.query('COMMIT'); return result; }
  catch(error) { await db.query('ROLLBACK'); throw error; } finally {db.release();}
}
// Also serializes cross-day corrections against a concurrent new check-in.
async function lockDay(db,employeeId,date) { await db.query('SELECT pg_advisory_xact_lock(hashtext($1))',[`timely:employee:${employeeId}`]); }
async function employeeList() { return (await pool.query('SELECT id,name,is_admin,schedule_profile,active FROM employees ORDER BY active DESC,name')).rows; }
function back(req,res,message) { req.session.flash=message; res.redirect(`/admin?week=${monday(validDate(req.body.week)?req.body.week:dateKey())}`); }
function parseLocal(value) {
  if(!value) return null;
  try { return fromLocal(value); } catch(error) { fail(error.message); }
}
async function loadPeriod(from,to) {
  const [entries,pauses,statuses]=await Promise.all([
    pool.query('SELECT * FROM time_entries WHERE date BETWEEN $1 AND $2 ORDER BY date,id',[from,to]),
    pool.query('SELECT b.* FROM breaks b JOIN time_entries t ON t.id=b.entry_id WHERE t.date BETWEEN $1 AND $2 ORDER BY b.start,b.id',[from,to]),
    pool.query('SELECT * FROM day_statuses WHERE date BETWEEN $1 AND $2',[from,to])
  ]);
  return {entries:entries.rows.map(e=>({...e,...summary(e,pauses.rows.filter(b=>b.entry_id===e.id))})),statuses:statuses.rows,breaks:pauses.rows};
}
async function entryForDay(db,employeeId,date) {
  let {rows}=await db.query('SELECT * FROM time_entries WHERE employee_id=$1 AND date=$2 ORDER BY id LIMIT 1 FOR UPDATE',[employeeId,date]);
  if(!rows.length) ({rows}=await db.query('INSERT INTO time_entries(employee_id,date) VALUES($1,$2) RETURNING *',[employeeId,date]));
  return rows[0];
}
async function requireOnsite(req,db) {
  const settings=await onsiteSettings(db);
  if(!settings.enabled) return;
  if(!parseNetworks(settings.networks).contains(req.ip)) fail('Buchung nur im Betriebs-WLAN möglich.',403);
  if(!validGrant(req.session.onsite,settings.token)) fail('Bitte zuerst den QR-Code im Betrieb erneut scannen.',403);
  // Consume in the same transaction as the booking: parallel requests cannot replay a scan.
  const grant=await db.query('DELETE FROM onsite_grants WHERE id=$1 AND qr_token=$2 AND expires>NOW() RETURNING id',[req.session.onsite.id,settings.token]);
  if(!grant.rows.length) fail('Dieser Scan wurde bereits verwendet oder ist abgelaufen. Bitte erneut scannen.',403);
}

app.get('/health',(req,res)=>res.send('OK'));
// Connection status reveals no employee, allowlist, QR token or client address.
app.get('/network-status',route(async(req,res)=>{
  const settings=await onsiteSettings();
  res.json({required:settings.enabled,atWork:settings.enabled && parseNetworks(settings.networks).contains(req.ip)});
}));
async function loginPage(req,res,error=null,status=200) {
  const settings=await onsiteSettings();
  const pairAvailable=settings.enabled && parseNetworks(settings.networks).contains(req.ip) && validGrant(req.session.onsite,settings.token);
  res.status(status).render('login',{employees:(await employeeList()).filter(e=>e.active),error,pairAvailable,adminLogin:req.query.admin==='1'||req.body.admin_login==='1',selectedEmployeeId:String(req.body.employee_id || req.session.user?.id || '')});
}
app.get('/login',route(async(req,res)=>loginPage(req,res)));
const attempts=new Map();
app.post('/login',route(async(req,res)=>{
  const ip=req.ip,now=Date.now();
  for(const [key,value] of attempts) if(value.until<=now) attempts.delete(key);
  const attempt=attempts.get(ip) || {count:0,until:now+10*60*1000};
  if(attempt.count>=15) fail('Zu viele Anmeldeversuche. Bitte in zehn Minuten erneut versuchen.',429);
  const {rows}=await pool.query('SELECT * FROM employees WHERE id=$1 AND active=TRUE',[integer(req.body.employee_id)]);
  const employee=rows[0];
  if(!employee || !sameSecret(String(req.body.pin || ''),employee.pin)) {
    attempt.count++; if(attempts.size<10000 || attempts.has(ip)) attempts.set(ip,attempt);
    return loginPage(req,res,'Falsche PIN oder Nutzer.',401);
  }
  const grant=req.session.onsite,token=deviceToken(req,production),existingDevice=await findDevice(pool,token);
  let pairedDevice=null,newToken=null;
  const wantsPair=req.body.remember_device==='on' && req.body.admin_login!=='1';
  if(wantsPair && existingDevice && existingDevice.employee_id!==employee.id) fail('Dieses Handy ist bereits einem anderen Mitarbeiter zugeordnet. Zuerst dessen Geräte-Verknüpfung aufheben.',409);
  await transaction(async db=>{
    const current=(await db.query('SELECT pin,auth_version,active FROM employees WHERE id=$1 FOR UPDATE',[employee.id])).rows[0];
    if(!current?.active || !sameSecret(current.pin,employee.pin) || current.auth_version!==employee.auth_version) fail('Die Kontodaten wurden geändert. Bitte erneut anmelden.',409);
    if(wantsPair) {
      const settings=await onsiteSettings(db);
      const scan=settings.enabled && parseNetworks(settings.networks).contains(req.ip) && validGrant(grant,settings.token)
        && (await db.query('SELECT id FROM onsite_grants WHERE id=$1 AND qr_token=$2 AND expires>NOW()',[grant.id,settings.token])).rows.length;
      if(!scan) fail('Zum Verknüpfen bitte im Betriebs-WLAN den QR-Code erneut scannen.',403);
      if(existingDevice) pairedDevice=existingDevice;
      else {
        const device=newDevice(),label=deviceLabel(req.body.device_label);
        await db.query('INSERT INTO remembered_devices(id,employee_id,token_hash,label,auth_version,expires_at) VALUES($1,$2,$3,$4,$5,$6)',[device.id,employee.id,tokenHash(device.token),label,employee.auth_version,new Date(Date.now()+deviceLifetime)]);
        pairedDevice={id:device.id,label};newToken=device.token;
        await db.query("INSERT INTO audit_log(actor_id,actor_name,employee_id,kind,after_data,reason) VALUES($1,$2,$1,'Gerät verknüpft',$3,'Mit persönlicher PIN und QR-Scan im Betriebsnetz bestätigt')",[employee.id,employee.name,JSON.stringify({id:device.id,label})]);
      }
    } else if(existingDevice?.employee_id===employee.id) pairedDevice=existingDevice;
  });
  attempts.delete(ip);
  await new Promise((resolve,reject)=>req.session.regenerate(error=>error?reject(error):resolve()));
  req.session.user={id:employee.id}; req.session.authVersion=employee.auth_version; req.session.authMethod='pin'; req.session.onsite=grant;
  if(pairedDevice) req.session.deviceId=pairedDevice.id;
  if(newToken) res.cookie(deviceCookieName(production),newToken,deviceCookieOptions(production));
  req.session.flash=newToken?'Dieses Handy ist jetzt mit deinem Konto verknüpft. Beim nächsten QR-Scan brauchst du keine PIN mehr.':undefined;
  res.redirect(req.body.admin_login==='1'&&employee.is_admin?'/admin':'/');
}));
app.get('/logout',(req,res)=>req.session.destroy(()=>res.redirect('/login')));
app.get('/vor-ort/:token',route(async(req,res)=>{
  const settings=await onsiteSettings();
  if(!settings.enabled || !sameSecret(req.params.token,settings.token)) fail('Dieser QR-Code ist nicht aktiv.',403);
  if(!parseNetworks(settings.networks).contains(req.ip)) fail('Bitte mit dem Betriebs-WLAN verbinden und den QR-Code erneut scannen.',403);
  const token=deviceToken(req,production),device=await findDevice(pool,token);
  if(device) {
    const keepPin=req.session.user?.id===device.employee_id && req.session.authMethod!=='device';
    await new Promise((resolve,reject)=>req.session.regenerate(error=>error?reject(error):resolve()));
    req.session.user={id:device.employee_id}; req.session.authVersion=device.auth_version;
    req.session.authMethod=keepPin?'pin':'device'; req.session.deviceId=device.id;
    await pool.query('UPDATE remembered_devices SET last_used_at=NOW(),expires_at=$1 WHERE id=$2 AND revoked_at IS NULL',[new Date(Date.now()+deviceLifetime),device.id]);
    res.cookie(deviceCookieName(production),token,deviceCookieOptions(production));
  } else if(token) clearDeviceCookie(res);
  const id=randomBytes(24).toString('hex'),expires=Date.now()+120000;
  await pool.query('DELETE FROM onsite_grants WHERE expires<=NOW()');
  await pool.query('INSERT INTO onsite_grants(id,qr_token,expires) VALUES($1,$2,$3)',[id,settings.token,new Date(expires)]);
  req.session.onsite={id,token:settings.token,expires};
  req.session.flash='QR-Code erkannt. Du kannst jetzt innerhalb von 2 Minuten eine Buchung bestätigen.';
  res.redirect(device?'/':'/login');
}));
app.get('/devices',auth,route(async(req,res)=>{
  res.render('devices',{devices:await listDevices(pool,req.session.user.id),currentDeviceId:req.session.deviceId || null});
}));
app.post('/devices/revoke',auth,route(async(req,res)=>{
  const id=String(req.body.id || '');
  if(!/^[a-f0-9-]{36}$/.test(id)) fail('Ungültige Geräteauswahl.');
  await transaction(async db=>{
    const device=(await db.query('UPDATE remembered_devices SET revoked_at=NOW() WHERE id=$1 AND employee_id=$2 AND revoked_at IS NULL RETURNING id,label',[id,req.session.user.id])).rows[0];
    if(!device) fail('Gerät nicht gefunden oder bereits gesperrt.',404);
    await audit(db,req,'Gerät gesperrt',req.session.user.id,null,device,null,'Verknüpfung durch Mitarbeiter aufgehoben');
  });
  if(id===req.session.deviceId) {
    clearDeviceCookie(res);
    return req.session.destroy(()=>res.redirect('/login'));
  }
  req.session.flash='Geräte-Verknüpfung aufgehoben. Dieses Gerät benötigt beim nächsten Scan wieder die PIN.';res.redirect('/devices');
}));
app.get('/',auth,route(async(req,res)=>{
  const user=req.session.user,date=dateKey();
  const {rows}=await pool.query('SELECT * FROM time_entries WHERE employee_id=$1 AND date=$2 ORDER BY id LIMIT 1',[user.id,date]);
  const entry=rows[0] || {id:null},pauses=entry.id?(await pool.query('SELECT * FROM breaks WHERE entry_id=$1 ORDER BY id',[entry.id])).rows:[];
  const settings=await onsiteSettings();
  const {rows:open}=await pool.query('SELECT date FROM time_entries WHERE employee_id=$1 AND date<$2 AND check_in IS NOT NULL AND check_out IS NULL ORDER BY date',[user.id,date]);
  res.render('index',{now:dayjs().tz(TZ),entry,summary:summary(entry,pauses),onBreak:pauses.some(b=>b.start&&!b.end),checkedIn:!!entry.check_in,checkedOut:!!entry.check_out,open,onsiteRequired:settings.enabled,onsiteReady:settings.enabled && parseNetworks(settings.networks).contains(req.ip) && validGrant(req.session.onsite,settings.token)});
}));
app.post('/action/:action(checkin|checkout|break-start|break-end)',auth,route(async(req,res)=>{
  const date=dateKey(),id=req.session.user.id;
  await transaction(async db=>{
    await lockDay(db,id,date); await requireOnsite(req,db);
    const entry=await entryForDay(db,id,date);
    const {rows:pauses}=await db.query('SELECT * FROM breaks WHERE entry_id=$1 ORDER BY id',[entry.id]);
    const open=pauses.find(b=>b.start&&!b.end),action=req.params.action;
    if(action==='checkin' && !entry.check_in) {
      const old=await db.query('SELECT id FROM time_entries WHERE employee_id=$1 AND check_in IS NOT NULL AND check_out IS NULL AND id<>$2',[id,entry.id]);
      if(old.rows.length) fail('Es gibt noch einen offenen Arbeitstag. Bitte den Admin um Korrektur bitten.',409);
      const status=(await db.query('SELECT status FROM day_statuses WHERE employee_id=$1 AND date=$2',[id,date])).rows[0]?.status;
      if(status && ['sick','leave','off','school'].includes(status)) fail('Für heute ist eine Abwesenheit hinterlegt. Bitte zuerst vom Admin klären lassen.',409);
      await db.query('UPDATE time_entries SET check_in=NOW(),revision=revision+1 WHERE id=$1',[entry.id]);
    } else if(action==='checkout' && entry.check_in && !entry.check_out) {
      await db.query('UPDATE breaks SET "end"=NOW() WHERE entry_id=$1 AND "end" IS NULL',[entry.id]);
      await db.query('UPDATE time_entries SET check_out=NOW(),revision=revision+1 WHERE id=$1',[entry.id]);
    } else if(action==='break-start' && entry.check_in && !entry.check_out && !open) {
      await db.query('INSERT INTO breaks(entry_id,start) VALUES($1,NOW())',[entry.id]);
      await db.query('UPDATE time_entries SET revision=revision+1 WHERE id=$1',[entry.id]);
    } else if(action==='break-end' && entry.check_in && !entry.check_out && open) {
      await db.query('UPDATE breaks SET "end"=NOW() WHERE id=$1',[open.id]);
      await db.query('UPDATE time_entries SET revision=revision+1 WHERE id=$1',[entry.id]);
    } else fail('Der Status hat sich geändert. Bitte die Seite neu laden.',409);
  });
  delete req.session.onsite; res.redirect('/');
}));
app.get('/history',auth,route(async(req,res)=>{
  const {rows}=await pool.query('SELECT * FROM time_entries WHERE employee_id=$1 ORDER BY date DESC,id DESC LIMIT 60',[req.session.user.id]);
  const {rows:pauses}=await pool.query('SELECT b.* FROM breaks b JOIN time_entries t ON t.id=b.entry_id WHERE t.employee_id=$1',[req.session.user.id]);
  const data=rows.map(e=>({...e,...summary(e,pauses.filter(b=>b.entry_id===e.id)),check_in:e.check_in?dayjs(e.check_in).tz(TZ).format('HH:mm'):null,check_out:e.check_out?dayjs(e.check_out).tz(TZ).format('HH:mm'):null}));
  res.render('history',{data});
}));

app.get('/admin',auth,admin,route(async(req,res)=>{
  const week=monday(req.query.week?checkDate(req.query.week):dateKey()),to=addDays(week,6),year=addDays(week,3).slice(0,4);
  const [employees,period,settings,yearStatuses,open,audits,devices]=await Promise.all([
    employeeList(),loadPeriod(week,to),onsiteSettings(),
    pool.query('SELECT * FROM day_statuses WHERE date BETWEEN $1 AND $2',[`${year}-01-01`,`${year}-12-31`]),
    pool.query('SELECT t.*,e.name FROM time_entries t JOIN employees e ON e.id=t.employee_id WHERE check_in IS NOT NULL AND check_out IS NULL ORDER BY date,e.name'),
    pool.query('SELECT a.*,e.name AS employee FROM audit_log a LEFT JOIN employees e ON e.id=a.employee_id ORDER BY a.id DESC LIMIT 30'),
    listDevices(pool)
  ]);
  const days=Array.from({length:7},(_,i)=>addDays(week,i));
  const rows=employees.filter(e=>e.active || period.entries.some(t=>t.employee_id===e.id) || period.statuses.some(s=>s.employee_id===e.id)).map(employee=>{
    const cells=days.map(date=>{
      const entries=period.entries.filter(t=>t.employee_id===employee.id&&t.date===date),status=period.statuses.find(s=>s.employee_id===employee.id&&s.date===date);
      return {date,entries,status,planned:plannedStatus(employee.schedule_profile,date,status?.planned_override),sick:countsSick(employee.schedule_profile,date,status?.status,status?.planned_override),closedMinutes:entries.filter(t=>t.check_out).reduce((sum,t)=>sum+t.netMinutes,0),open:entries.some(t=>t.check_in&&!t.check_out)};
    });
    return {employee,cells,minutes:cells.reduce((sum,c)=>sum+c.closedMinutes,0),sick:cells.filter(c=>c.sick).length,yearSick:yearStatuses.rows.filter(s=>s.employee_id===employee.id&&countsSick(employee.schedule_profile,s.date,s.status,s.planned_override)).length};
  });
  const url=baseUrl(),qrUrl=url?`${url}/vor-ort/${settings.token}`:null;
  const qrImage=qrUrl?await QRCode.toDataURL(qrUrl,{width:400,margin:4,errorCorrectionLevel:'M'}):null;
  res.render('admin',{employees,rows,days,week,to,year,weekTitle:weekNumber(week),previous:addDays(week,-7),next:addDays(week,7),profiles,statusLabels,onsiteConfig:settings,ip:normalizeIp(req.ip),qrUrl,qrImage,open:open.rows,audits:audits.rows,plannedStatus,devices,currentDeviceId:req.session.deviceId || null});
}));
// Admin-only setup diagnostics: no cookies, credentials or arbitrary headers are exposed.
app.get('/admin/network-info',auth,admin,(req,res)=>{
  const addresses=String(req.headers['x-forwarded-for'] || '').split(',').map(value=>normalizeIp(value.trim()));
  res.json({clientIp:normalizeIp(req.ip),socketAddress:normalizeIp(req.socket.remoteAddress),forwardedFor:addresses.filter(value=>isIP(value)),trustedProxyCount:Number(process.env.TRUST_PROXY || 0)});
});
app.post('/admin/devices/revoke',auth,admin,route(async(req,res)=>{
  const id=String(req.body.id || ''),why=reason(req.body.reason);
  if(!/^[a-f0-9-]{36}$/.test(id)) fail('Ungültige Geräteauswahl.');
  await transaction(async db=>{
    const device=(await db.query('UPDATE remembered_devices SET revoked_at=NOW() WHERE id=$1 AND revoked_at IS NULL RETURNING id,employee_id,label',[id])).rows[0];
    if(!device) fail('Gerät nicht gefunden oder bereits gesperrt.',404);
    await audit(db,req,'Gerät gesperrt',device.employee_id,null,device,null,why);
  });
  if(id===req.session.deviceId) {
    clearDeviceCookie(res);
    return req.session.destroy(()=>res.redirect('/login'));
  }
  back(req,res,'Gerät gesperrt. Es kann erst nach erneuter PIN-Anmeldung wieder verknüpft werden.');
}));
app.get('/admin/entries/edit',auth,admin,route(async(req,res)=>{
  const employeeId=integer(req.query.employee_id),date=checkDate(req.query.date),entryId=req.query.id?integer(req.query.id):null;
  const {rows}=await pool.query('SELECT id,name FROM employees WHERE id=$1',[employeeId]);
  if(!rows.length) fail('Mitarbeiter nicht gefunden.',404);
  const {rows:entries}=await pool.query('SELECT * FROM time_entries WHERE employee_id=$1 AND date=$2 ORDER BY id',[employeeId,date]);
  const entry=entryId?entries.find(e=>e.id===entryId):entries[0];
  if(entryId&&!entry) fail('Buchung nicht gefunden.',404);
  const pauses=entry?(await pool.query('SELECT * FROM breaks WHERE entry_id=$1 ORDER BY start',[entry.id])).rows:[];
  res.render('edit-entry',{employee:rows[0],date,entry,pauses,week:monday(date)});
}));
app.get('/admin/qr',auth,admin,route(async(req,res)=>{
  const config=await onsiteSettings(),url=baseUrl();
  if(!url) fail('Bitte zuerst die öffentliche App-Adresse als APP_URL am Server einrichten.');
  const qrImage=await QRCode.toDataURL(`${url}/vor-ort/${config.token}`,{width:600,margin:4,errorCorrectionLevel:'M'});
  res.render('qr',{qrImage,enabled:config.enabled});
}));
app.post('/admin/entries/save',auth,admin,route(async(req,res)=>{
  const employeeId=integer(req.body.employee_id),date=checkDate(req.body.date),why=reason(req.body.reason),start=parseLocal(req.body.check_in),end=parseLocal(req.body.check_out);
  if(!start) fail('Bitte einen Beginn angeben.');
  if(dateKey(start)!==date) fail('Der Beginn muss am ausgewählten Tag liegen.');
  if(new Date(start)>new Date() || (end&&new Date(end)>new Date())) fail('Zeiten dürfen nicht in der Zukunft liegen.');
  const gross=end?Math.floor((new Date(end)-new Date(start))/60000):null;
  if(end && (gross<=0 || gross>24*60)) fail('Das Ende muss nach dem Beginn und innerhalb von 24 Stunden liegen.');
  const pause=req.body.break_minutes===''?null:Number(req.body.break_minutes);
  if(pause!==null && (!Number.isInteger(pause)||pause<0||pause>1440||(gross!==null&&pause>gross))) fail('Ungültige Pausendauer.');
  await transaction(async db=>{
    await lockDay(db,employeeId,date);
    const {rows:existing}=await db.query('SELECT * FROM time_entries WHERE employee_id=$1 AND date=$2 ORDER BY id FOR UPDATE',[employeeId,date]);
    const entry=req.body.id?existing.find(e=>e.id===integer(req.body.id)):null;
    if((req.body.id&&!entry) || (!req.body.id&&existing.length) || (entry&&String(entry.revision)!==req.body.revision)) fail('Die Buchung wurde inzwischen geändert. Bitte neu öffnen.',409);
    const status=(await db.query('SELECT status FROM day_statuses WHERE employee_id=$1 AND date=$2',[employeeId,date])).rows[0]?.status;
    if(status&&status!=='work') fail('Bitte zuerst die eingetragene Abwesenheit entfernen oder auf Arbeitstag setzen.');
    const {rows:overlap}=await db.query("SELECT id FROM time_entries WHERE employee_id=$1 AND id<>$2 AND check_in IS NOT NULL AND check_in<COALESCE($3::timestamptz,'infinity'::timestamptz) AND COALESCE(check_out,'infinity'::timestamptz)>$4::timestamptz",[employeeId,entry?.id || 0,end,start]);
    if(overlap.length) fail('Die Zeit überschneidet sich mit einer anderen oder offenen Buchung.');
    const pauses=entry?(await db.query('SELECT * FROM breaks WHERE entry_id=$1 ORDER BY start',[entry.id])).rows:[];
    for(const b of pauses) if(b.start && (new Date(b.start)<new Date(start) || (end&&(new Date(b.start)>new Date(end)||(b.end&&new Date(b.end)>new Date(end)))))) fail('Vorhandene Pausen liegen außerhalb der neuen Zeit. Bitte die Zeiten prüfen.');
    const originalPause=summary({check_in:start,check_out:end},pauses).breakMinutes;
    if(gross!==null && (pause??originalPause)>gross) fail('Die Pausen sind länger als die Gesamtzeit.');
    let updated;
    if(entry) {
      updated=(await db.query('UPDATE time_entries SET check_in=$1,check_out=$2,break_minutes_override=$3,revision=revision+1 WHERE id=$4 RETURNING *',[start,end,pause,entry.id])).rows[0];
      if(end) await db.query('UPDATE breaks SET "end"=$1 WHERE entry_id=$2 AND "end" IS NULL',[end,entry.id]);
    } else updated=(await db.query('INSERT INTO time_entries(employee_id,date,check_in,check_out,break_minutes_override) VALUES($1,$2,$3,$4,$5) RETURNING *',[employeeId,date,start,end,pause])).rows[0];
    const afterPauses=(await db.query('SELECT * FROM breaks WHERE entry_id=$1 ORDER BY start',[updated.id])).rows;
    await audit(db,req,'Zeitkorrektur',employeeId,date,{entry:entry || null,breaks:pauses},{entry:updated,breaks:afterPauses},why);
  });
  back(req,res,'Zeitkorrektur gespeichert und protokolliert.');
}));
app.post('/admin/days/save',auth,admin,route(async(req,res)=>{
  const employeeId=integer(req.body.employee_id),from=checkDate(req.body.from),to=checkDate(req.body.to),why=reason(req.body.reason),status=req.body.status;
  if(to<from || to>addDays(from,366)) fail('Bitte einen Zeitraum von höchstens 367 Tagen wählen.');
  if(status!=='clear'&&!Object.hasOwn(statusLabels,status)) fail('Ungültiger Tagesstatus.');
  const override=req.body.planned_override || null;
  if(override&&!['work','off','school'].includes(override)) fail('Ungültiger Arbeitsplan.');
  await transaction(async db=>{
    if(!(await db.query('SELECT id FROM employees WHERE id=$1',[employeeId])).rows.length) fail('Mitarbeiter nicht gefunden.',404);
    for(let date=from;date<=to;date=addDays(date,1)) {
      await lockDay(db,employeeId,date);
      const before=(await db.query('SELECT * FROM day_statuses WHERE employee_id=$1 AND date=$2 FOR UPDATE',[employeeId,date])).rows[0] || null;
      if(!['clear','work'].includes(status) && (await db.query('SELECT id FROM time_entries WHERE employee_id=$1 AND date=$2 AND check_in IS NOT NULL',[employeeId,date])).rows.length) fail(`Am ${date} sind Arbeitszeiten vorhanden. Abwesenheit nicht gespeichert.`);
      let after=null;
      if(status==='clear') await db.query('DELETE FROM day_statuses WHERE employee_id=$1 AND date=$2',[employeeId,date]);
      else after=(await db.query('INSERT INTO day_statuses(employee_id,date,status,planned_override) VALUES($1,$2,$3,$4) ON CONFLICT(employee_id,date) DO UPDATE SET status=EXCLUDED.status,planned_override=EXCLUDED.planned_override,revision=day_statuses.revision+1 RETURNING *',[employeeId,date,status,override])).rows[0];
      await audit(db,req,'Tagesstatus',employeeId,date,before,after,why);
    }
  });
  back(req,res,'Tagesstatus gespeichert. Krankheitstage zählen nur an geplanten Arbeitstagen.');
}));
app.post('/admin/employees/:action(add|update|deactivate)',auth,admin,route(async(req,res)=>{
  const action=req.params.action,id=action==='add'?null:integer(req.body.id),why=reason(req.body.reason || 'Mitarbeiterverwaltung');
  await transaction(async db=>{
    await db.query("SELECT pg_advisory_xact_lock(hashtext('timely-employees'))");
    const before=id?(await db.query('SELECT id,name,is_admin,schedule_profile,active FROM employees WHERE id=$1 FOR UPDATE',[id])).rows[0]:null;
    if(id&&!before) fail('Mitarbeiter nicht gefunden.',404);
    if(action==='deactivate') {
      if(id===req.session.user.id) fail('Das eigene Konto kann nicht deaktiviert werden.');
      const after=(await db.query('UPDATE employees SET active=FALSE,auth_version=auth_version+1 WHERE id=$1 RETURNING id,name,is_admin,schedule_profile,active',[id])).rows[0];
      await db.query('UPDATE remembered_devices SET revoked_at=NOW() WHERE employee_id=$1 AND revoked_at IS NULL',[id]);
      await audit(db,req,'Mitarbeiter',id,null,before,after,why); return;
    }
    const name=String(req.body.name||'').trim(),pin=String(req.body.pin||''),isAdmin=req.body.is_admin==='on',profile=req.body.schedule_profile || defaultProfile(name);
    if(!name||name.length>100||!Object.hasOwn(profiles,profile) || (action==='add'&&!/^\d{4,6}$/.test(pin)) || (pin&&!/^\d{4,6}$/.test(pin))) fail('Bitte Name, Arbeitsplan und eine PIN mit 4–6 Ziffern prüfen.');
    if(id===req.session.user.id&&(!isAdmin||req.body.active!=='on')) fail('Eigene Admin-Rechte und das eigene Konto müssen aktiv bleiben.');
    const after=action==='add'
      ?(await db.query('INSERT INTO employees(name,pin,is_admin,schedule_profile) VALUES($1,$2,$3,$4) RETURNING id,name,is_admin,schedule_profile,active',[name,pin,isAdmin,profile])).rows[0]
      :(await db.query("UPDATE employees SET name=$1,pin=CASE WHEN $2='' THEN pin ELSE $2 END,is_admin=$3,schedule_profile=$4,active=$5,auth_version=auth_version+CASE WHEN $2<>'' OR NOT $5 THEN 1 ELSE 0 END WHERE id=$6 RETURNING id,name,is_admin,schedule_profile,active",[name,pin,isAdmin,profile,req.body.active==='on',id])).rows[0];
    if(action==='update' && (pin || !after.active)) await db.query('UPDATE remembered_devices SET revoked_at=NOW() WHERE employee_id=$1 AND revoked_at IS NULL',[id]);
    await audit(db,req,'Mitarbeiter',after.id,null,before,{...after,pin_changed:!!pin},why);
  });
  back(req,res,'Mitarbeiter gespeichert.');
}));
app.post('/admin/onsite',auth,admin,route(async(req,res)=>{
  const enabled=req.body.enabled==='on',networks=parseNetworks(req.body.networks);
  if(networks.networks.length>20) fail('Höchstens 20 Betriebsnetze erlauben.');
  if(enabled && (!networks.networks.length || !baseUrl())) fail('Zur Aktivierung Betriebsnetz und APP_URL (öffentliche HTTPS-Adresse) einrichten.');
  if(enabled && !networks.contains(req.ip)) fail('Bitte aus dem Betriebs-WLAN aktivieren. Der aktuelle Anschluss muss in der Liste stehen.');
  await transaction(async db=>{
    const before=(await db.query("SELECT value FROM app_settings WHERE key='onsite' FOR UPDATE")).rows[0].value;
    const after={enabled,networks:networks.networks.join('\n'),token:req.body.rotate==='on'?newQrToken():before.token};
    await db.query("UPDATE app_settings SET value=$1 WHERE key='onsite'",[JSON.stringify(after)]);
    await audit(db,req,'Vor-Ort-Einstellung',null,null,{enabled:before.enabled,networks:before.networks},{enabled,networks:after.networks,qr_replaced:req.body.rotate==='on'},reason(req.body.reason));
  });
  back(req,res,'Vor-Ort-Einstellung gespeichert. Bei neuem QR-Code bitte den Ausdruck ersetzen.');
}));
app.get('/admin/export',auth,admin,route(async(req,res)=>{
  const from=checkDate(req.query.from),to=checkDate(req.query.to);
  if(to<from||to>addDays(from,366)) fail('Bitte einen Zeitraum von höchstens 367 Tagen wählen.');
  const [period,employees]=await Promise.all([loadPeriod(from,to),employeeList()]);
  const workbook=new ExcelJS.Workbook(),ws=workbook.addWorksheet('Zeiten');
  ws.columns=[{header:'Datum',key:'date',width:12},{header:'Mitarbeiter',key:'employee',width:24},{header:'Check-In',key:'start',width:21},{header:'Check-Out',key:'end',width:21},{header:'Pausen (Min)',key:'pause',width:15},{header:'Netto (Std)',key:'net',width:15},{header:'Status',key:'status',width:22}];
  for(const entry of period.entries) ws.addRow({date:entry.date,employee:employees.find(e=>e.id===entry.employee_id)?.name,start:entry.check_in?dayjs(entry.check_in).tz(TZ).format('DD.MM.YYYY HH:mm'):'',end:entry.check_out?dayjs(entry.check_out).tz(TZ).format('DD.MM.YYYY HH:mm'):'',pause:entry.breakMinutes,net:entry.check_out?entry.netMinutes/60:null,status:entry.check_in&&!entry.check_out?'Offen · nicht summiert':entry.check_out?'Abgeschlossen':'Ohne Buchung'});
  const abs=workbook.addWorksheet('Tagesstatus');
  abs.columns=[{header:'Datum',key:'date',width:12},{header:'Mitarbeiter',key:'employee',width:24},{header:'Status',key:'status',width:18},{header:'Krankheitstag gezählt',key:'sick',width:25}];
  for(const status of period.statuses) {
    const employee=employees.find(e=>e.id===status.employee_id);
    abs.addRow({date:status.date,employee:employee?.name,status:statusLabels[status.status],sick:countsSick(employee?.schedule_profile,status.date,status.status,status.planned_override)?1:0});
  }
  const weekly=workbook.addWorksheet('Wochen');
  weekly.columns=[{header:'Woche ab',key:'week',width:12},{header:'Mitarbeiter',key:'employee',width:24},{header:'Netto (Std)',key:'hours',width:15},{header:'Krankheitstage',key:'sick',width:18},{header:'Offene Buchungen',key:'open',width:20}];
  const groups=[];
  for(const employee of employees) {
    const dates=new Set([...period.entries,...period.statuses].filter(e=>e.employee_id===employee.id).map(e=>monday(e.date)));
    for(const week of dates) {
      const entries=period.entries.filter(e=>e.employee_id===employee.id&&monday(e.date)===week),statuses=period.statuses.filter(e=>e.employee_id===employee.id&&monday(e.date)===week);
      groups.push({week,employee:employee.name,hours:entries.filter(e=>e.check_out).reduce((sum,e)=>sum+e.netMinutes,0)/60,sick:statuses.filter(s=>countsSick(employee.schedule_profile,s.date,s.status,s.planned_override)).length,open:entries.filter(e=>e.check_in&&!e.check_out).length});
    }
  }
  groups.sort((a,b)=>a.week.localeCompare(b.week)||a.employee.localeCompare(b.employee)).forEach(row=>weekly.addRow(row));
  for(const sheet of workbook.worksheets) {sheet.getRow(1).font={bold:true};sheet.views=[{state:'frozen',ySplit:1}];}
  res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition',`attachment; filename="timely_${from}_${to}.xlsx"`);
  await workbook.xlsx.write(res); res.end();
}));
app.use((error,req,res,next)=>{
  if(res.headersSent) return next(error);
  const status=error.status || (error.code==='23505'?409:500);
  if(status===500) console.error('Timely request failed:',error.code || error.name);
  if(status===500 && !production) console.error(error.stack);
  res.status(status).render('error',{message:status===500?'Die Anfrage konnte nicht gespeichert werden. Bitte erneut versuchen.':error.code==='23505'?'Dieser Name ist bereits vergeben.':error.message});
});
app.listen(process.env.PORT || 3000,process.env.HOST || '0.0.0.0',()=>console.log(`Timely listening on port ${process.env.PORT || 3000}`));
