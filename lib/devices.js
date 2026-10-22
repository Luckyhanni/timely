import { createHash, randomBytes, randomUUID } from 'node:crypto';

export const deviceLifetime = 365 * 24 * 60 * 60 * 1000;
export const deviceCookieName = production => production ? '__Host-timely_device' : 'timely_device';
export const deviceCookieOptions = production => ({httpOnly:true,secure:production,sameSite:'lax',path:'/',maxAge:deviceLifetime});

export function deviceToken(req, production) {
  const values=String(req.headers.cookie || '').split(';').map(value=>value.trim()).filter(value=>value.startsWith(`${deviceCookieName(production)}=`));
  if(values.length!==1) return null;
  const token=values[0].slice(values[0].indexOf('=')+1);
  return /^[a-f0-9]{64}$/.test(token) ? token : null;
}
export function tokenHash(token) { return createHash('sha256').update(token).digest('hex'); }
export function newDevice() { return {id:randomUUID(),token:randomBytes(32).toString('hex')}; }
export function deviceLabel(value) { return String(value || 'Mein Handy').trim().slice(0,80) || 'Mein Handy'; }

export async function findDevice(db,token) {
  if(!token) return null;
  return (await db.query(`SELECT d.id,d.employee_id,d.label,d.auth_version,e.name,e.is_admin
    FROM remembered_devices d JOIN employees e ON e.id=d.employee_id
    WHERE d.token_hash=$1 AND d.revoked_at IS NULL AND d.expires_at>NOW()
      AND e.active=TRUE AND e.auth_version=d.auth_version`,[tokenHash(token)])).rows[0] || null;
}

export async function listDevices(db,employeeId=null) {
  return (await db.query(`SELECT d.id,d.employee_id,d.label,d.created_at,d.last_used_at,d.expires_at,e.name
    FROM remembered_devices d JOIN employees e ON e.id=d.employee_id
    WHERE d.revoked_at IS NULL AND d.expires_at>NOW() AND e.active=TRUE AND e.auth_version=d.auth_version
      AND ($1::integer IS NULL OR d.employee_id=$1)
    ORDER BY e.name,d.last_used_at DESC`,[employeeId])).rows;
}
