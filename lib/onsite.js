import { BlockList, isIP } from 'node:net';
import { randomBytes } from 'node:crypto';

export function newQrToken() { return randomBytes(32).toString('hex'); }
export function normalizeIp(value) { return value?.startsWith('::ffff:') && isIP(value.slice(7)) === 4 ? value.slice(7) : value; }
export function parseNetworks(value) {
  const list = new BlockList();
  const networks = String(value || '').split(/[\s,;]+/).filter(Boolean);
  for (const network of networks) {
    const [raw,bits,...rest] = network.split('/');
    const ip = normalizeIp(raw), version = isIP(ip), max = version === 4 ? 32 : 128;
    if (!version || rest.length || (bits !== undefined && (!/^\d+$/.test(bits) || +bits < 1 || +bits > max))) {
      const error=new Error('Bitte gültige IPv4-/IPv6-Adressen oder Netze eingeben (kein /0).'); error.status=400; throw error;
    }
    const type = version === 4 ? 'ipv4' : 'ipv6';
    if (bits === undefined) list.addAddress(ip,type); else list.addSubnet(ip,+bits,type);
  }
  return { networks, contains(value) { const ip=normalizeIp(value),v=isIP(ip); return !!v && list.check(ip,v===4?'ipv4':'ipv6'); } };
}
export function validGrant(grant, token, now = Date.now()) {
  return !!grant && grant.token === token && Number.isFinite(grant.expires) && grant.expires > now;
}
