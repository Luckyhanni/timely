import test from 'node:test';
import assert from 'node:assert/strict';
import { deviceLifetime,deviceCookieName,deviceCookieOptions,deviceToken,tokenHash,newDevice,deviceLabel } from '../lib/devices.js';

test('production device cookie is host-only, secure, HTTP-only and persistent',()=>{
  assert.equal(deviceCookieName(true),'__Host-timely_device');
  assert.deepEqual(deviceCookieOptions(true),{httpOnly:true,secure:true,sameSite:'lax',path:'/',maxAge:365*86400000});
  assert.equal(deviceLifetime,365*86400000);
});
test('device keys are random and only hashes are used for database lookup',()=>{
  const a=newDevice(),b=newDevice();assert.match(a.token,/^[a-f0-9]{64}$/);assert.notEqual(a.token,b.token);assert.notEqual(a.id,b.id);
  assert.match(a.id,/^[a-f0-9-]{36}$/);assert.notEqual(tokenHash(a.token),a.token);assert.equal(tokenHash(a.token),tokenHash(a.token));
});
test('malformed, duplicate and unrelated device cookies fail closed',()=>{
  const token='a'.repeat(64),read=cookie=>deviceToken({headers:{cookie}},true);
  assert.equal(read(`connect.sid=test; __Host-timely_device=${token}`),token);
  for(const cookie of [undefined,'',`timely_device=${token}`,`__Host-timely_device=${token}; __Host-timely_device=${token}`,'__Host-timely_device=oops',`__Host-timely_device=${token}%00`]) assert.equal(read(cookie),null);
});
test('device labels are bounded and have a readable default',()=>{
  assert.equal(deviceLabel('   '),'Mein Handy');assert.equal(deviceLabel('  Mein Telefon  '),'Mein Telefon');assert.equal(deviceLabel('a'.repeat(100)).length,80);
});
