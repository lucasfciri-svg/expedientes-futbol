'use strict';
/* ===== Utilidades ===== */
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enc = new TextEncoder();
async function sha256Hex(data) {
  const buf = typeof data === 'string' ? enc.encode(data) : data;
  const h = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
}
const K256 = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
// SHA-256 incremental: WebCrypto no hashea por partes y un video entero en memoria puede colgar el celular.
class Sha256 {
  constructor() { this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]); this.buf = new Uint8Array(64); this.bl = 0; this.len = 0; this.w = new Uint32Array(64); }
  block(d, o) {
    const w = this.w, h = this.h;
    for (let i = 0; i < 16; i++) w[i] = (d[o + 4 * i] << 24) | (d[o + 4 * i + 1] << 16) | (d[o + 4 * i + 2] << 8) | d[o + 4 * i + 3];
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], b = w[i - 2];
      w[i] = (w[i - 16] + (((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)) + w[i - 7] + (((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10))) | 0;
    }
    let A = h[0], B = h[1], C = h[2], D = h[3], E = h[4], F = h[5], G = h[6], H = h[7];
    for (let i = 0; i < 64; i++) {
      const t1 = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + K256[i] + w[i]) | 0;
      const t2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C))) | 0;
      H = G; G = F; F = E; E = (D + t1) | 0; D = C; C = B; B = A; A = (t1 + t2) | 0;
    }
    h[0] += A; h[1] += B; h[2] += C; h[3] += D; h[4] += E; h[5] += F; h[6] += G; h[7] += H;
  }
  update(d) {
    let i = 0; this.len += d.length;
    if (this.bl) {
      i = Math.min(64 - this.bl, d.length); this.buf.set(d.subarray(0, i), this.bl); this.bl += i;
      if (this.bl < 64) return this;
      this.block(this.buf, 0); this.bl = 0;
    }
    for (; i + 64 <= d.length; i += 64) this.block(d, i);
    if (i < d.length) { this.buf.set(d.subarray(i)); this.bl = d.length - i; }
    return this;
  }
  hex() {
    const bits = this.len * 8, pad = new Uint8Array((this.bl < 56 ? 56 : 120) - this.bl + 8);
    pad[0] = 0x80; const dv = new DataView(pad.buffer);
    dv.setUint32(pad.length - 8, Math.floor(bits / 2 ** 32)); dv.setUint32(pad.length - 4, bits >>> 0);
    this.update(pad);
    return [...this.h].map(x => x.toString(16).padStart(8, '0')).join('');
  }
}
async function sha256File(f, onProgress) {
  if (f.size <= 64 * 2 ** 20) return sha256Hex(await f.arrayBuffer());
  const h = new Sha256(), CH = 4 * 2 ** 20;
  for (let o = 0; o < f.size; o += CH) {
    h.update(new Uint8Array(await f.slice(o, o + CH).arrayBuffer()));
    if (onProgress) onProgress(Math.min(1, (o + CH) / f.size));
  }
  return h.hex();
}
function stable(v) {
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
const fmt = (iso) => iso ? new Date(iso).toLocaleString('es-AR', { timeZone: 'America/Argentina/Buenos_Aires', dateStyle: 'short', timeStyle: 'short' }) : '—';
const fmtD = (iso) => iso ? new Date(iso).toLocaleDateString('es-AR', { timeZone: 'America/Argentina/Buenos_Aires' }) : '—';
const uid = () => Math.random().toString(36).slice(2, 10);
const hostOf = (u) => { try { return new URL(/^https?:/i.test(u) ? u : 'https://' + u).hostname.toLowerCase(); } catch { return ''; } };
const regDomain = (h) => (h || '').split('.').slice(-2).join('.');
function toast(m) { const t = $('#toast'); t.textContent = m; t.classList.add('on'); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove('on'), 2600); }
function download(name, content, type = 'application/json') {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}
const b64ToBlob = (b64, type) => new Blob([Uint8Array.from(atob(b64), c => c.charCodeAt(0))], { type });

/* ===== Datos base ===== */
const TEAMS = ['Aldosivi', 'Argentinos Juniors', 'Atlético Tucumán', 'Banfield', 'Barracas Central', 'Belgrano', 'Boca Juniors', 'Central Córdoba de Santiago del Estero', 'Defensa y Justicia', 'Deportivo Riestra', 'Estudiantes de La Plata', 'Estudiantes de Río Cuarto', 'Gimnasia y Esgrima de La Plata', 'Gimnasia y Esgrima de Mendoza', 'Huracán', 'Independiente', 'Independiente Rivadavia', 'Instituto', 'Lanús', "Newell's Old Boys", 'Platense', 'Racing Club', 'River Plate', 'Rosario Central', 'San Lorenzo', 'Sarmiento', 'Talleres de Córdoba', 'Tigre', 'Unión de Santa Fe', 'Vélez Sarsfield'];
const SEED_LIC = [
  { code: 'ESP', name: 'ESPN Premium (Disney)', domains: ['espn.com.ar', 'espn.com', 'disneyplus.com', 'bamgrid.com', 'dssott.com'] },
  { code: 'TNT', name: 'TNT Sports (Warner Bros. Discovery)', domains: ['tntsports.com.ar', 'max.com', 'hbomax.com'] },
  { code: 'DTV', name: 'DIRECTV / DGO', domains: ['directv.com.ar', 'directvgo.com', 'dgo.com'] },
  { code: 'FLW', name: 'Flow (Telecom)', domains: ['flow.com.ar', 'personal.com.ar', 'telecom.com.ar'] },
  { code: 'TLC', name: 'Telecentro', domains: ['telecentro.com.ar', 'telecentroplay.com.ar'] },
  { code: 'MOV', name: 'Movistar TV', domains: ['movistar.com.ar', 'movistarplay.com.ar'] },
];
const DB_KEY = 'xf_db_v1';
let DB = load();
function load() {
  try { const d = JSON.parse(localStorage.getItem(DB_KEY)); if (d && d.cases) { d.cases = d.cases.filter(c => !c.demo); d.matches = d.matches.filter(m => m.source !== 'demo'); return d; } } catch {}
  return { matches: [], licensees: SEED_LIC.map(l => ({ ...l, id: uid() })), marks: [], cases: [], audit: [], seq: 0, flags: {} };
}
function save() { localStorage.setItem(DB_KEY, JSON.stringify(DB)); }
let REMOTE = [];

async function audit(action, caseId, detail) {
  const prev = DB.audit.length ? DB.audit[DB.audit.length - 1].hash : '0'.repeat(64);
  const e = { i: DB.audit.length, ts: new Date().toISOString(), action, caseId: caseId || null, detail: detail || '', prev };
  e.hash = await sha256Hex(stable(e));
  DB.audit.push(e); save();
}
async function verifyAudit(list = DB.audit) {
  let prev = '0'.repeat(64);
  for (const e of list) {
    const { hash, ...rest } = e;
    if (rest.prev !== prev) return { ok: false, at: e.i, why: 'cadena rota (prev no coincide)' };
    if (await sha256Hex(stable(rest)) !== hash) return { ok: false, at: e.i, why: 'registro alterado' };
    prev = hash;
  }
  return { ok: true, n: list.length };
}

/* ===== Partidos ===== */
async function loadFixtures() {
  try { const r = await fetch('/api/fixtures'); const j = await r.json(); REMOTE = j.matches || []; } catch { REMOTE = []; }
}
function allMatches() {
  const m = new Map(); for (const x of REMOTE) m.set(x.id, x); for (const x of DB.matches) m.set(x.id, x);
  for (const c of DB.cases) if (c.match && !m.has(c.match.id)) m.set(c.match.id, c.match);
  return [...m.values()].sort((a, b) => (b.kickoff || '').localeCompare(a.kickoff || ''));
}
const matchById = (id) => allMatches().find(m => m.id === id);
const matchName = (m) => m ? `${m.home} vs ${m.away}` : '—';
async function matchCode(id) { return (await sha256Hex('match:' + id)).slice(0, 6).toUpperCase(); }

/* ===== Marca de agua =====
   Formato de payload forense: AR-<PARTIDO 6>-<LIC 3>-<SESION 8>-<CTRL 4>
   CTRL = primeros 4 hex de SHA-256 del resto. El detector forense del proveedor extrae el payload del video;
   la plataforma lo valida contra el partido, el licenciatario y el registro de emisión. */
async function makePayload(mid, lic, session) {
  const body = `AR-${await matchCode(mid)}-${lic}-${session.toUpperCase()}`;
  return `${body}-${(await sha256Hex(body)).slice(0, 4).toUpperCase()}`;
}
async function checkWatermark(c, payload) {
  const p = (payload || '').trim().toUpperCase();
  const res = { payload: p, checkedAt: new Date().toISOString(), checks: [], verdict: 'bad' };
  const m = p.match(/^AR-([0-9A-F]{6})-([A-Z]{3})-([0-9A-F]{8})-([0-9A-F]{4})$/);
  if (!m) { res.checks.push({ ok: false, t: 'Formato de payload inválido (esperado AR-XXXXXX-LIC-XXXXXXXX-XXXX).' }); return res; }
  const body = p.slice(0, -5);
  const ctrlOk = (await sha256Hex(body)).slice(0, 4).toUpperCase() === m[4];
  res.checks.push({ ok: ctrlOk, t: ctrlOk ? 'Dígito de control válido: el payload no fue adulterado.' : 'Dígito de control inválido: lectura errónea o payload adulterado.' });
  const mc = await matchCode(c.match.id);
  const matchOk = mc === m[1];
  let other = null;
  if (!matchOk) for (const x of allMatches()) if (await matchCode(x.id) === m[1]) { other = x; break; }
  res.checks.push({ ok: matchOk, t: matchOk ? `Corresponde al partido ${matchName(c.match)} (código ${mc}).` : `No corresponde a este partido${other ? ` (es de ${matchName(other)})` : ''}.` });
  const lic = DB.licensees.find(l => l.code === m[2]);
  res.licensee = lic ? { code: lic.code, name: lic.name, domains: lic.domains } : null;
  res.checks.push({ ok: !!lic, t: lic ? `Señal emitida al licenciatario ${lic.name}.` : `Código de licenciatario ${m[2]} desconocido.` });
  const hosts = [hostOf(c.target), c.analysis && c.analysis.deliveryHost].filter(Boolean);
  const authAll = DB.licensees.flatMap(l => l.domains.map(d => [d, l]));
  const legit = hosts.map(h => authAll.find(([d]) => h === d || h.endsWith('.' + d))).find(Boolean);
  res.checks.push({ ok: !legit, t: legit ? `El dominio ${hosts.join(' / ')} pertenece a ${legit[1].name}: es distribución AUTORIZADA, no corresponde expediente.` : `Se exhibe en ${hosts.join(' / ')}, que no es dominio de ningún licenciatario autorizado.` });
  const issued = DB.marks.find(k => k.payload === p);
  res.issued = issued || null;
  res.checks.push({ ok: !!issued, soft: true, t: issued ? `Figura en el registro de emisión: sesión ${issued.session}${issued.note ? ' · ' + issued.note : ''} (origen de la fuga).` : 'No figura en el registro de emisión importado (cargá el export del sistema de marcas para identificar la sesión de origen).' });
  const hard = res.checks.filter(x => !x.soft);
  res.verdict = hard.every(x => x.ok) ? 'ok' : 'bad';
  return res;
}

/* ===== Conocimiento / reincidencia ===== */
function knowledge(excludeId) {
  const dom = new Map(), ip = new Map(), asn = new Map();
  const add = (map, k, c, extra) => { if (!k) return; const e = map.get(k) || { key: k, cases: new Set(), matches: new Set(), last: null, ...extra }; e.cases.add(c.id); e.matches.add(c.match.id); if (!e.last || c.createdAt > e.last) e.last = c.createdAt; map.set(k, e); };
  for (const c of DB.cases) {
    if (c.id === excludeId) continue;
    add(dom, regDomain(hostOf(c.target)), c, { role: 'reproductor' });
    for (const h of (c.analysis && c.analysis.hosts) || []) {
      add(dom, regDomain(h.host), c, { role: h.roles.join('/') });
      for (const i of h.ips) { add(ip, i.ip, c, { asn: i.asn }); add(asn, i.asn && 'AS' + i.asn, c, { holder: i.holder, kind: i.kind }); }
    }
  }
  return { dom, ip, asn };
}
function reincidence(c) {
  const k = knowledge(c.id);
  const hits = [];
  const doms = new Set([regDomain(hostOf(c.target)), ...((c.analysis && c.analysis.hosts) || []).map(h => regDomain(h.host))]);
  for (const d of doms) if (k.dom.has(d)) hits.push({ type: 'dominio', key: d, n: k.dom.get(d).cases.size });
  for (const h of (c.analysis && c.analysis.hosts) || []) for (const i of h.ips) {
    if (k.ip.has(i.ip)) hits.push({ type: 'IP', key: i.ip, n: k.ip.get(i.ip).cases.size });
    if (i.kind !== 'cdn' && i.kind !== 'cloud' && k.asn.has('AS' + i.asn)) hits.push({ type: 'ASN', key: 'AS' + i.asn, n: k.asn.get('AS' + i.asn).cases.size });
  }
  const seen = new Set(); return hits.filter(h => !seen.has(h.type + h.key) && seen.add(h.type + h.key));
}

/* ===== Vencimiento propuesto ===== */
function proposeExpiry(c) {
  const ko = new Date(c.match.kickoff || c.createdAt);
  const rein = reincidence(c);
  const maxN = Math.max(0, ...rein.filter(r => r.type !== 'ASN').map(r => r.n));
  const dh = c.analysis && c.analysis.hosts.find(h => h.host === c.analysis.deliveryHost);
  const ipOk = dh && dh.collateral && dh.collateral.recommendation === 'bloquear_ip_y_dominio';
  const add = (d, h) => new Date(d.getTime() + h * 3600e3);
  let days, why;
  if (maxN >= 3) { days = null; why = `Reincidente en ${maxN} expedientes previos: bloqueo hasta fin de temporada.`; }
  else if (maxN >= 1) { days = 90; why = `Reincidente (${maxN} expediente/s previo/s): 90 días.`; }
  else { days = 30; why = 'Primera detección: 30 días, renovable con nueva evidencia.'; }
  const season = new Date(Date.UTC(ko.getUTCFullYear(), 11, 31, 23, 59));
  const domainUntil = days == null ? season : add(ko, days * 24);
  const items = [{ target: `Dominio del reproductor (${hostOf(c.target)})`, method: 'DNS + SNI', until: domainUntil.toISOString() }];
  if (dh && dh.host !== hostOf(c.target)) items.push({ target: `Dominio de entrega de video (${dh.host})`, method: 'DNS + SNI', until: domainUntil.toISOString() });
  if (ipOk) items.push({ target: `IP de entrega ${dh.a.join(', ')} (AS${dh.ips[0] && dh.ips[0].asn})`, method: 'IP (bloqueo dinámico en vivo)', until: add(ko, 3).toISOString(), note: 'Ventana del partido + 1 h; se renueva fecha a fecha.' });
  else if (dh) items.push({ target: `IP de entrega ${dh.a.join(', ')}`, method: 'NO bloquear por IP', until: null, note: dh.collateral ? dh.collateral.reason : '' });
  return { proposedAt: new Date().toISOString(), why, items };
}

/* ===== Solidez del expediente ===== */
function score(c) {
  const dh = c.analysis && c.analysis.hosts && c.analysis.hosts.find(h => h.host === c.analysis.deliveryHost);
  const items = [
    ['Página analizada (host, IP y ASN)', 10, !!(c.analysis && c.analysis.hosts && c.analysis.hosts.some(h => h.host === hostOf(c.target) && h.a && h.a.length))],
    ['Marca de agua verificada (partido + licenciatario + dominio no autorizado)', 20, c.watermark && c.watermark.verdict === 'ok'],
    ['Servidor de video identificado (host + IP)', 15, !!(dh && dh.a.length)],
    ['Proveedor (ASN) identificado', 10, !!(dh && dh.ips[0] && dh.ips[0].asn)],
    ['Riesgo colateral evaluado', 10, !!(dh && dh.collateral)],
    ['Capturas con hash SHA-256', 10, c.captures.length > 0],
    ['Capturas con sello de tiempo RFC 3161' + (c.captures.some(x => x.tsa && x.tsa.demo) ? ' (sello simulado DEMO: no suma)' : ''), 10, c.captures.length > 0 && c.captures.every(x => realTsa(x.tsa))],
    ['Promoción del enlace documentada', 5, c.promos.length > 0],
    ['Vencimiento propuesto', 5, !!c.expiry],
    ['Expediente sellado' + (c.seal && c.seal.tsa && c.seal.tsa.demo ? ' (sello simulado DEMO: no suma)' : ''), 5, !!(c.seal && realTsa(c.seal.tsa))],
  ];
  return { items, pct: items.reduce((s, [, w, ok]) => s + (ok ? w : 0), 0) };
}

/* ===== Router ===== */
const routes = { panel: vPanel, partidos: vPartidos, expedientes: vExpedientes, exp: vExp, nuevo: vNuevo, conocimiento: vConocimiento, licencias: vLicencias, pruebas: vPruebas, verificar: vVerificar, auditoria: vAuditoria, informe: vInforme };
async function route() {
  const [path, qs] = (location.hash.slice(2) || 'panel').split('?');
  const [name, arg] = path.split('/');
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === '#/' + (name === 'exp' || name === 'nuevo' ? 'expedientes' : name)));
  const fn = routes[name] || vPanel;
  $('#app').innerHTML = await fn(arg, new URLSearchParams(qs || ''));
  window.scrollTo(0, 0);
  if (fn.after) fn.after(arg);
}
window.addEventListener('hashchange', route);
const go = (h) => { if (location.hash === h) route(); else location.hash = h; };

/* ===== Vistas ===== */
const hero = (b, t) => `<section class="hero"><p><b>${esc(b)}</b> ${esc(t)}</p></section>`;
const TEAM_COLORS = { 'Aldosivi': ['#00843D', '#FFD100'], 'Argentinos Juniors': ['#D7182A', '#FFFFFF'], 'Atlético Tucumán': ['#6CACE4', '#FFFFFF'], 'Banfield': ['#00703C', '#FFFFFF'], 'Barracas Central': ['#C8102E', '#FFFFFF'], 'Belgrano': ['#5BB4E5', '#0B2D6B'], 'Boca Juniors': ['#003C8F', '#FDB913'], 'Central Córdoba de Santiago del Estero': ['#111111', '#FFFFFF'], 'Defensa y Justicia': ['#00A651', '#FFE600'], 'Deportivo Riestra': ['#0A0A0A', '#FFFFFF'], 'Estudiantes de La Plata': ['#E30613', '#FFFFFF'], 'Estudiantes de Río Cuarto': ['#4FA3D9', '#FFFFFF'], 'Gimnasia y Esgrima de La Plata': ['#0B2D6B', '#FFFFFF'], 'Gimnasia y Esgrima de Mendoza': ['#1A1A1A', '#FFFFFF'], 'Huracán': ['#F2F2F2', '#E4002B'], 'Independiente': ['#D50032', '#FFFFFF'], 'Independiente Rivadavia': ['#0033A0', '#FFFFFF'], 'Instituto': ['#D52B1E', '#FFFFFF'], 'Lanús': ['#7A1F2B', '#FFFFFF'], "Newell's Old Boys": ['#CE1126', '#0A0A0A'], 'Platense': ['#5C3A21', '#FFFFFF'], 'Racing Club': ['#75AADB', '#FFFFFF'], 'River Plate': ['#FFFFFF', '#E30613'], 'Rosario Central': ['#003DA5', '#FFD700'], 'San Lorenzo': ['#002F6C', '#E4002B'], 'Sarmiento': ['#00843D', '#FFFFFF'], 'Talleres de Córdoba': ['#002855', '#FFFFFF'], 'Tigre': ['#003DA5', '#E4002B'], 'Unión de Santa Fe': ['#E4002B', '#FFFFFF'], 'Vélez Sarsfield': ['#FFFFFF', '#0033A0'] };
const initials = (n) => (n || '?').replace(/de |y |Club|Atlético |Deportivo /g, '').split(/\s+/).filter(Boolean).slice(0, 2).map(w => w[0]).join('').toUpperCase();
function crest(team, badge) {
  const [bg, ac] = TEAM_COLORS[team] || ['#1A1A1A', '#42A500'];
  return `<div class="crest" style="--bg:${bg};--ac:${ac}">${badge ? `<img src="${esc(badge)}" alt="${esc(team)}" loading="lazy">` : `<svg viewBox="0 0 60 70" aria-hidden="true"><path d="M30 3 56 12v22c0 17-12 28-26 33C16 62 4 51 4 34V12z" fill="none" stroke="${ac}" stroke-width="3"/><text x="30" y="43" text-anchor="middle" font-size="19" font-weight="800" fill="${ac}">${esc(initials(team))}</text></svg>`}</div>`;
}
function matchTiles(list) {
  return `<div class="tiles">${list.map((m, i) => {
    const n = DB.cases.filter(c => c.match.id === m.id).length;
    return `<a class="tile" href="#/nuevo?match=${encodeURIComponent(m.id)}"><div class="pair">${crest(m.home, m.homeBadge)}${crest(m.away, m.awayBadge)}</div><div class="tinfo"><span class="fig">FIG ${i + 1}.0</span><b>${esc(m.home)}</b><b>${esc(m.away)}</b><small>${fmt(m.kickoff)}</small>${n ? `<span class="pill warn">${n} exp.</span>` : ''}</div></a>`;
  }).join('')}</div>`;
}
const sec = (label, html) => `<section class="sec"><h3 class="lbl">${esc(label)}</h3><div>${html}</div></section>`;
function matchRow(m, extra = '') {
  const n = DB.cases.filter(c => c.match.id === m.id).length;
  return `<div class="item"><div class="row sp"><div class="match">${crest(m.home, m.homeBadge)}<div><b>${esc(matchName(m))}</b><div class="small mut">${fmt(m.kickoff)}${m.round ? ' · Fecha ' + esc(m.round) : ''}${m.venue ? ' · ' + esc(m.venue) : ''}${m.score ? ' · ' + esc(m.score) : ''}</div></div>${crest(m.away, m.awayBadge)}</div>
  <div class="row">${n ? `<span class="pill warn">${n} exp.</span>` : ''}<a class="btn" href="#/nuevo?match=${encodeURIComponent(m.id)}">+ Expediente</a>${extra}</div></div></div>`;
}
function caseRow(c) {
  const s = score(c);
  const dh = c.analysis && c.analysis.deliveryHost;
  return `<a class="item" href="#/exp/${c.id}"><div class="row sp"><b>${esc(c.num)} · ${esc(hostOf(c.target))}</b><span>${estadoPill(c)} ${c.seal ? '<span class="pill ok">Sellado</span>' : '<span class="pill warn">Borrador</span>'}</span></div>
  <div class="small mut">${esc(matchName(c.match))} · ${fmt(c.createdAt)}${dh ? ' · video: ' + esc(dh) : ''}${''}</div>
  <div class="bar" style="margin-top:6px"><i style="width:${s.pct}%"></i></div></a>`;
}

async function vPanel() {
  const cs = DB.cases, sealed = cs.filter(c => c.seal).length;
  const k = knowledge();
  const now = Date.now();
  const upcoming = allMatches().filter(m => new Date(m.kickoff).getTime() > now - 3 * 3600e3).sort((a, b) => a.kickoff.localeCompare(b.kickoff)).slice(0, 4);
  const cdn = cs.filter(c => c.analysis && c.analysis.hosts.some(h => h.host === c.analysis.deliveryHost && h.collateral.recommendation === 'bloquear_dominio')).length;
  return `${hero('Expedientes', 'arma la prueba contra cada stream pirata del fútbol argentino: señal oficial, servidor que entrega el video, riesgo colateral y evidencia sellada.')}
  <div class="grid">
    <div class="kpi"><b>${cs.length}</b><span>Expedientes</span></div>
    <div class="kpi"><b>${sealed}</b><span>Sellados</span></div>
    <div class="kpi"><b>${k.dom.size}</b><span>Dominios relevados</span></div>
    <div class="kpi"><b>${k.asn.size}</b><span>Proveedores (ASN)</span></div>
    <div class="kpi"><b>${cdn}</b><span>Con IP en CDN/compartida → bloquear dominio</span></div>
  </div>
  ${sec('Próximos partidos', upcoming.length ? matchTiles(upcoming) : '<p>Sin partidos próximos cargados. <a href="#/partidos">Agregar partido</a></p>')}
  <div class="card"><div class="row sp"><h2>Últimos expedientes</h2><a href="#/expedientes">Ver todos</a></div><div class="list">${cs.slice(-5).reverse().map(caseRow).join('') || '<p class="mut">Todavía no hay expedientes.</p>'}</div>
  <div class="row"><a class="btn" href="#/nuevo">+ Nuevo expediente</a><a class="btn" href="#/informe">Informe general (PDF)</a></div></div>
  <section class="sec"><h3 class="lbl">Cómo funciona</h3><div class="prose"><b>Así se arma un expediente.</b> Elegís el partido, pegás el enlace pirata y la plataforma sigue la cadena página → reproductor embebido → manifiesto de video → segmentos, para llegar al servidor que realmente entrega el video (host, IP, ASN). Evalúa cuántos sitios comparten esa IP, verifica la marca de agua forense contra el partido y el licenciatario, calcula hashes SHA-256 y pide sellos de tiempo RFC 3161 a una autoridad externa. Cada acción queda en un registro de auditoría encadenado por hash.</div></section>`;
}

async function vPartidos() {
  const ms = allMatches();
  return `${hero('Partidos', 'de la Liga Profesional. Cada expediente queda atado a un partido concreto.')}
  <div class="card"><h2>Agregar partido</h2>
    <div class="grid"><div><label>Local</label><select id="mHome">${TEAMS.map(t => `<option>${esc(t)}</option>`).join('')}</select></div>
    <div><label>Visitante</label><select id="mAway">${TEAMS.map((t, i) => `<option ${i === 1 ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></div>
    <div><label>Fecha y hora (Argentina)</label><input id="mKo" type="datetime-local"></div>
    <div><label>Competencia</label><input id="mComp" value="Liga Profesional de Fútbol"></div></div>
    <div class="row" style="margin-top:10px"><button onclick="addMatch()">Agregar</button></div></div>
  <div class="card"><div class="row sp"><h2>Fixture (${ms.length})</h2><button class="ghost" onclick="loadFixtures().then(route)">Actualizar</button></div>
  <p class="small mut">Fuente automática: TheSportsDB (Liga Profesional). Los partidos que no aparezcan se cargan a mano arriba.</p>
  <div class="list">${ms.map(m => matchRow(m)).join('') || '<p class="mut">Sin partidos.</p>'}</div></div>`;
}
window.addMatch = async () => {
  const home = $('#mHome').value, away = $('#mAway').value, ko = $('#mKo').value;
  if (home === away) return toast('Local y visitante iguales');
  if (!ko) return toast('Poné fecha y hora');
  const m = { id: 'm-' + uid(), home, away, kickoff: new Date(ko + ':00-03:00').toISOString(), league: $('#mComp').value, source: 'manual' };
  DB.matches.push(m); save(); await audit('partido_agregado', null, matchName(m) + ' ' + m.kickoff); toast('Partido agregado: ahora pegá el enlace pirata'); location.hash = '#/nuevo?match=' + encodeURIComponent(m.id);
};

async function vNuevo(_, qs) {
  const ms = allMatches(); const sel = qs.get('match') || (DB.matches.filter(x => x.source === 'manual').slice(-1)[0] || {}).id;
  return `${hero('Nuevo expediente', 'en tres datos: el partido, el enlace pirata y, si lo tenés, el video.')}<div class="card">
  <label>Partido</label><select id="nMatch">${ms.map(m => `<option value="${esc(m.id)}" ${m.id === sel ? 'selected' : ''}>${esc(matchName(m))} · ${fmtD(m.kickoff)}</option>`).join('')}</select>
  <label>URL de la página pirata (donde se ve el reproductor)</label><input id="nUrl" placeholder="https://sitio-pirata.xyz/canal/tnt" inputmode="url">
  <label>URL del video (.m3u8) — opcional, si la tenés de las herramientas de red</label><input id="nVid" placeholder="https://cdn.ejemplo/live/index.m3u8" inputmode="url">
  <label>Detectado por / notas</label><input id="nNote" placeholder="Monitoreo, denuncia de usuario, etc.">
  <label class="small" style="display:flex;gap:8px;align-items:center;margin-top:10px"><input type="checkbox" id="nSeal" style="width:auto"> Sellar el expediente al terminar (después ya no se puede agregar la marca de agua ni promociones sin abrir una versión nueva)</label>
  <p class="small mut">“Crear y verificar” sigue la página hasta el reproductor y el .m3u8, comprueba que sea un streaming de fútbol (reproductor, partido, canal, dominio no autorizado) y que esté en vivo, baja segmentos del stream y saca un fotograma para el detector de marca de agua. Cada pieza queda con SHA-256 y sello RFC 3161, junto con el HTML de la página. Para probarlo: <a href="#/nuevo" onclick="$('#nUrl').value=location.origin+'/prueba/en-vivo.html';return false">usar la página de prueba</a>.</p>
  <div class="row" style="margin-top:12px"><button onclick="createCase(true)">Crear y verificar</button><button class="ghost" onclick="createCase(false)">Solo crear</button></div>
  </div>`;
}
window.createCase = async (run) => {
  const m = matchById($('#nMatch').value); const url = $('#nUrl').value.trim(); const sealAfter = !!($('#nSeal') && $('#nSeal').checked);
  if (!m) return toast('Elegí un partido'); if (!hostOf(url)) return toast('URL inválida');
  DB.seq++;
  const c = { id: uid(), num: `EXP-${new Date().getFullYear()}-${String(DB.seq).padStart(4, '0')}`, createdAt: new Date().toISOString(), version: 1,
    match: { id: m.id, home: m.home, away: m.away, kickoff: m.kickoff, round: m.round || null, venue: m.venue || null, league: m.league || 'Liga Profesional de Fútbol' },
    target: /^https?:/i.test(url) ? url : 'https://' + url, videoUrl: $('#nVid').value.trim() || null, notes: $('#nNote').value.trim(),
    analysis: null, analysisTsa: null, watermark: null, captures: [], promos: [], expiry: null, seal: null };
  DB.cases.push(c); save(); await audit('expediente_creado', c.id, `${c.num} ${c.target}`);
  location.hash = '#/exp/' + c.id;
  if (run) setTimeout(() => autoVerify(c.id, sealAfter), 300);
};

async function vExpedientes(_, qs) {
  const q = (qs.get('q') || '').toLowerCase(), st = qs.get('st') || '', mt = qs.get('m') || '';
  const hay = (c) => [c.num, c.target, matchName(c.match), c.notes, c.watermark && c.watermark.payload, c.analysis && JSON.stringify(c.analysis.hosts.map(h => [h.host, h.a, h.ips.map(i => [i.asn, i.holder])])), c.promos.map(p => p.url + p.account).join(' ')].join(' ').toLowerCase();
  const list = DB.cases.filter(c => (!q || hay(c).includes(q)) && (!st || (st === 's' ? c.seal : !c.seal)) && (!mt || c.match.id === mt)).reverse();
  const ms = [...new Map(DB.cases.map(c => [c.match.id, c.match])).values()];
  return `${hero('Expedientes', 'para buscar y auditar por dominio, IP, proveedor, marca de agua o cuenta.')}
  <div class="card"><div class="grid"><div><label>Buscar (dominio, IP, ASN, proveedor, marca, cuenta)</label><input id="fq" value="${esc(q)}" placeholder="ej: AS13335, 185.x, futbollibre"></div>
  <div><label>Estado</label><select id="fst"><option value="">Todos</option><option value="b" ${st === 'b' ? 'selected' : ''}>Borrador</option><option value="s" ${st === 's' ? 'selected' : ''}>Sellado</option></select></div>
  <div><label>Partido</label><select id="fm"><option value="">Todos</option>${ms.map(m => `<option value="${esc(m.id)}" ${m.id === mt ? 'selected' : ''}>${esc(matchName(m))}</option>`).join('')}</select></div></div>
  <div class="row" style="margin-top:10px"><button onclick="filt()">Filtrar</button><a class="btn ghost" href="#/nuevo">+ Nuevo</a><button class="ghost" onclick="exportAll()">Exportar todo</button><label class="btn ghost" style="margin:0">Importar<input type="file" accept=".json" hidden onchange="importAll(this.files[0])"></label></div></div>
  <div class="card"><div class="list">${list.map(caseRow).join('') || '<p class="mut">Sin resultados.</p>'}</div></div>`;
}
window.filt = () => go(`#/expedientes?q=${encodeURIComponent($('#fq').value)}&st=${$('#fst').value}&m=${encodeURIComponent($('#fm').value)}`);

/* --- Detalle de expediente --- */
const getCase = (id) => DB.cases.find(c => c.id === id);
function hostCard(h, isDelivery) {
  const i0 = h.ips[0] || {};
  const col = h.collateral || {};
  return `<div class="card" style="background:var(--card2)"><div class="row sp"><b class="mono" style="font-size:14px">${esc(h.host)}</b><span>${h.roles.map(r => `<span class="pill ${r === 'segmentos' || r === 'manifiesto' ? 'bad' : 'info'}">${esc(r)}</span>`).join(' ')}</span></div>
  ${isDelivery ? '<div class="small" style="color:var(--bad);margin-top:4px">▶ Servidor que entrega el video</div>' : ''}
  <table><tr><th>IP</th><td class="mono">${esc(h.a.join(', ') || '—')}${h.aaaa.length ? '<br>' + esc(h.aaaa.join(', ')) : ''}</td></tr>
  ${h.cname.length ? `<tr><th>CNAME</th><td class="mono">${esc(h.cname.join(' → '))}</td></tr>` : ''}
  <tr><th>ASN</th><td>${i0.asn ? `<b>AS${i0.asn}</b> · ${esc(i0.holder || '')}` : '—'}${i0.prefix ? `<div class="small mut mono">${esc(i0.prefix)}</div>` : ''}</td></tr>
  <tr><th>País</th><td>${esc(i0.country || '—')}${i0.city ? ' · ' + esc(i0.city) : ''}</td></tr>
  <tr><th>Tipo</th><td>${i0.kind === 'cdn' ? '<span class="pill bad">CDN</span>' : i0.kind === 'cloud' ? '<span class="pill warn">Nube pública</span>' : i0.kind === 'hosting' ? '<span class="pill info">Hosting/VPS</span>' : '<span class="pill">sin clasificar</span>'} ${esc(i0.kindLabel || '')} ${h.cdnCname || h.cdnHeader ? `<span class="small mut">(detectado por ${h.cdnCname ? 'CNAME' : 'cabeceras'}: ${esc(h.cdnCname || h.cdnHeader)})</span>` : ''}</td></tr>
  <tr><th>Comparten IP</th><td>${h.reverse ? (h.reverse.ok ? `<b>${h.reverse.count}${h.reverse.count >= 500 ? '+' : ''}</b> dominios <details><summary>ver muestra</summary><div class="mono">${h.reverse.domains.map(esc).join('<br>')}</div></details>` : `<span class="mut">${esc(h.reverse.note)}</span>`) : '<span class="mut">no consultado</span>'}</td></tr>
  <tr><th>Riesgo colateral</th><td><span class="pill ${col.level === 'alto' ? 'bad' : col.level === 'medio' ? 'warn' : col.level === 'bajo' ? 'ok' : ''}">${esc(col.level || '—')}</span> <div class="small">${esc(col.reason || '')}</div></td></tr>
  <tr><th>Recomendación</th><td><b>${col.recommendation === 'bloquear_ip_y_dominio' ? 'Bloquear IP + dominio' : 'Bloquear por DOMINIO (no por IP)'}</b></td></tr></table></div>`;
}
function tsaBox(t, label) {
  if (!t) return '';
  if (t.error) return `<div class="stamp small" style="border-color:var(--bad)">Sello no obtenido: ${esc(t.error)}</div>`;
  if (t.demo) return `<div class="stamp small" style="border-color:var(--warn)"><span class="pill warn">DEMO</span> <b>${esc(label || 'Sello de tiempo')}</b>: sello simulado (${esc(t.genTime)}), sin valor probatorio y sin .tsr. No suma solidez ni se puede publicar. Las TSAs no respondieron: ${esc(t.reason || '')}</div>`;
  return `<div class="stamp small">🕒 <b>${esc(label || 'Sello de tiempo')}</b>: ${fmt(t.genTime)} (${esc(t.genTime)}) · ${esc(t.tsa)} · ${t.imprintPresent ? 'hash incluido en el sello ✔' : 'revisar'}</div>`;
}
function verifyHint(hash, t) {
  if (!realTsa(t)) return '';
  const ca = !t.tsaId || t.tsaId === 'freetsa' ? '-CAfile cacert.pem -untrusted tsa.crt' : '-CAfile /etc/ssl/certs/ca-certificates.crt';
  const note = !t.tsaId || t.tsaId === 'freetsa' ? 'certificados en freetsa.org' : 'el certificado de la TSA viene dentro del sello; la raíz está en el almacén del sistema';
  return `<p class="small mut">Verificación externa: <span class="mono">openssl ts -verify -digest ${esc(hash)} -in sello.tsr ${ca}</span> (${note}).</p>`;
}
async function vExp(id) {
  const c = getCase(id); if (!c) return '<p>Expediente no encontrado. <a href="#/expedientes">Volver</a></p>';
  const a = c.analysis, s = score(c), rein = reincidence(c);
  const dh = a && a.hosts.find(h => h.host === a.deliveryHost);
  const ro = !!c.seal;
  const wm = c.watermark;
  return `<div class="row sp"><h1>${esc(c.num)} ${c.demo ? '<span class="pill warn">DEMO</span>' : ''}</h1><div class="row noprint"><button onclick="downloadPdf('${esc(c.num)}_v${c.version}')">Descargar informe PDF</button><button class="ghost" onclick="window.print()">Imprimir</button><button class="ghost" onclick="exportCase('${c.id}')">JSON</button></div></div>
  <div class="card"><div class="row sp"><div><b>${esc(matchName(c.match))}</b><div class="small mut">${esc(c.match.league || '')} · ${fmt(c.match.kickoff)}${c.match.venue ? ' · ' + esc(c.match.venue) : ''}</div></div>${c.seal ? '<span class="pill ok">Sellado v' + c.version + '</span>' : '<span class="pill warn">Borrador v' + c.version + '</span>'}</div>
  <table style="margin-top:8px"><tr><th>Enlace pirata</th><td class="mono">${esc(c.target)}</td></tr><tr><th>Creado</th><td>${fmt(c.createdAt)}</td></tr>${c.notes ? `<tr><th>Notas</th><td>${esc(c.notes)}</td></tr>` : ''}</table>
  ${a ? `<div class="verdict ${dh ? 'bad' : 'warn'}" style="margin-top:10px"><b>Resultado del análisis</b> (${fmt(a.finishedAt || a.startedAt)})<br>${a.hosts.map(h => `<span class="mono">${esc(h.host)}</span> · ${esc((h.a || []).join(', ') || 'sin IP')}${h.ips && h.ips[0] ? ` · AS${esc(h.ips[0].asn)} ${esc(h.ips[0].holder || '')}` : ''}`).join('<br>')}<br>${dh ? `Video entregado por <span class="mono">${esc(dh.host)}</span>` : 'No se encontró reproductor ni video en esta página. Si lo tenés, pegá la URL del video (.m3u8) en el paso 2.0 y volvé a analizar.'}</div>` : `<div class="verdict warn noprint" style="margin-top:10px">Todavía no se analizó: tocá «Analizar» en el paso 2.0.</div>`}
  <h3>Solidez del expediente: ${s.pct}%</h3><div class="bar"><i style="width:${s.pct}%"></i></div>
  <ul class="check small">${s.items.map(([t, w, ok]) => `<li>${ok ? '<i class="ck y"></i>' : '<i class="ck"></i>'} ${esc(t)} <span class="mut">(${w})</span></li>`).join('')}</ul>
  ${rein.length ? `<div class="verdict warn">⚠ Reincidencia detectada: ${rein.map(r => `${esc(r.type)} ${esc(r.key)} en ${r.n} exp.`).join(' · ')}</div>` : ''}</div>

  ${streamCard(c, ro)}
  <div class="card step ${wm ? (wm.verdict === 'ok' ? 'done' : 'bad') : ''}"><div class="fig">PASO 1.0</div><h2>Prueba de señal oficial (marca de agua)</h2>
  <p class="small mut">Pegá el payload que devolvió el detector forense al analizar la captura del stream. La plataforma verifica que corresponde a este partido y a qué licenciatario se emitió, y que el sitio no es un dominio propio de ese licenciatario.</p>
  ${ro ? '' : `<div class="row"><input id="wmIn" class="mono" placeholder="AR-XXXXXX-LIC-XXXXXXXX-XXXX" value="${esc(wm ? wm.payload : '')}" style="flex:1"><button onclick="doWatermark('${c.id}')">Verificar</button></div>`}
  ${wm ? `<div class="verdict ${wm.verdict}">${wm.verdict === 'ok' ? '✔ Señal oficial redistribuida sin autorización' : '✖ La marca no prueba señal oficial no autorizada'}</div>
  <div class="mono">${esc(wm.payload)}</div><ul class="check small">${wm.checks.map(x => `<li>${x.ok ? '<i class="ck y"></i>' : x.soft ? '<i class="ck w"></i>' : '<i class="ck n"></i>'} ${esc(x.t)}</li>`).join('')}</ul><div class="small mut">Verificado ${fmt(wm.checkedAt)}</div>` : ''}</div>

  <div class="card step ${dh ? 'done' : a ? 'warn' : ''}"><div class="fig">PASO 2.0</div><h2>Servidor que entrega el video</h2>
  <p class="small mut">Bloquear la página que muestra el reproductor no corta el video: el análisis sigue los iframes y manifiestos hasta el host que sirve los segmentos.</p>
  ${ro || c.demo ? '' : `<label>URL del video (.m3u8/.mpd) si la conocés</label><div class="row"><input id="vidIn" class="mono" value="${esc(c.videoUrl || '')}" placeholder="opcional" style="flex:1"><button id="anBtn" onclick="runAnalysis('${c.id}')">${a ? 'Re-analizar' : 'Analizar'}</button></div>`}
  <div id="anStatus"></div>
  ${a ? `
   ${a.notes.map(n => `<div class="verdict warn small">${esc(n)}</div>`).join('')}
   ${dh ? `<div class="verdict bad">Video entregado por <span class="mono">${esc(dh.host)}</span> · ${esc(dh.a.join(', '))} · AS${esc(dh.ips[0] && dh.ips[0].asn)} ${esc(dh.ips[0] && dh.ips[0].holder || '')}</div>` : ''}
   <h3>Cadena de carga</h3><div class="chain small">${a.chain.map(n => `<div style="margin-left:${n.depth * 14}px;margin-bottom:6px">${n.depth ? '↳ iframe ' : '● página '}<span class="mono">${esc(n.finalUrl || n.url)}</span> ${n.status ? `<span class="pill">${n.status}</span>` : ''} ${n.error ? `<span class="pill bad">${esc(n.error)}</span>` : ''}${n.title ? `<div class="mut">“${esc(n.title)}”</div>` : ''}${n.sha256 ? `<div class="mut mono">HTML sha256 ${esc(n.sha256)}</div>` : ''}</div>`).join('')}
   ${a.video.map(v => `<div style="margin-bottom:6px">▶ ${esc(v.type || 'video')} <span class="mono">${esc(v.url)}</span> ${v.status ? `<span class="pill">${v.status}</span>` : ''}${v.segments.length ? `<div class="mut mono">segmentos: ${esc(v.segments[0])}</div>` : ''}</div>`).join('')}</div>
   <h3>Infraestructura y riesgo colateral (punto 3)</h3>${a.hosts.sort((x, y) => (y.host === a.deliveryHost) - (x.host === a.deliveryHost)).map(h => hostCard(h, h.host === a.deliveryHost)).join('')}
   ${a.rdap.length ? `<h3>Registro de dominio (RDAP)</h3><div class="tbl"><table><tr><th>Dominio</th><th>Registrador</th><th>Abuso</th><th>Alta</th><th>Vence</th></tr>${a.rdap.map(r => `<tr><td class="mono">${esc(r.domain)}</td><td>${esc(r.registrar || '—')}</td><td class="mono">${esc(r.abuse || '—')}</td><td>${fmtD(r.created)}</td><td>${fmtD(r.expires)}</td></tr>`).join('')}</table></div>` : ''}
   <div class="small mut" style="margin-top:6px">Análisis ${fmt(a.startedAt)} · ${esc(a.analyzer)} · hash del informe <span class="mono">${esc(a.reportSha256)}</span></div>
   ${tsaBox(c.analysisTsa, 'Sello del informe técnico')}${!ro && c.analysisTsa && !realTsa(c.analysisTsa) ? `<div class="row noprint" style="margin-top:6px"><button class="ghost" onclick="restampReport('${c.id}')">Reintentar sello</button></div>` : ''}` : ''}</div>

  <div class="card step ${c.captures.length ? (c.captures.every(x => realTsa(x.tsa)) ? 'done' : 'warn') : ''}"><div class="fig">PASO 4.0</div><h2>Capturas: hashes y sellos de tiempo</h2>
  <p class="small mut">El archivo no sale de tu teléfono: el SHA-256 se calcula localmente y solo el hash viaja a la autoridad de sellado (RFC 3161: FreeTSA y, si no responde, Sectigo). Guardá el archivo original: cualquier alteración cambia el hash.</p>
  ${ro ? '' : `<button onclick="autoCaptureBtn('${c.id}')">Capturar la página automáticamente</button> <label class="btn">+ Agregar capturas (foto/video)<input type="file" multiple accept="image/*,video/*" hidden onchange="addCaptures('${c.id}',this.files)"></label>`}
  <div id="capStatus"></div>
  <div class="thumbs" style="margin:8px 0">${c.captures.filter(x => x.thumb).map(x => `<img src="${x.thumb}" alt="">`).join('')}</div>
  ${c.captures.map((x, i) => `<div class="card" style="background:var(--card2)"><div class="row sp"><b>${esc(x.name)}</b><span class="small mut">${(x.size / 1024).toFixed(0)} KB · ${esc(x.type)}</span></div>
   <div class="mono">SHA-256 ${esc(x.sha256)}</div><div class="small mut">Registrada ${fmt(x.addedAt)}</div>${x.thumb && x.kind === 'fotograma' ? `<img src="${x.thumb}" alt="" style="max-width:220px;border-radius:6px;margin:6px 0">` : ''}${x.kind === 'fotograma' && x.source ? `<div class="small mut">Fotograma ${esc(x.source.width)}×${esc(x.source.height)} del segmento ${esc(x.source.seq)} (SHA-256 ${esc((x.source.fromSegmentSha256 || '').slice(0, 16))}…), sacado en el navegador</div>` : ''}${x.source && x.source.finalUrl ? `<div class="small mut">Descargada de ${esc(x.source.finalUrl)} · HTTP ${esc(x.source.httpStatus)}${x.kind === 'segmento' ? ` · segmento ${esc(x.source.seq)}${x.source.live ? ' · en vivo' : ''}${x.source.programDateTime ? ' · hora en el stream ' + esc(x.source.programDateTime) : ''}` : ''}${x.source.title ? ' · “' + esc(x.source.title) + '”' : ''}${x.source.hops && x.source.hops.length ? ` · ${x.source.hops.length} redirección(es)` : ''}${x.source.truncated ? ' · truncada a 2 MB' : ''}</div>` : ''}${tsaBox(x.tsa)}
   <div class="row noprint" style="margin-top:6px">${x.data64 || x.html64 ? `<button class="ghost" onclick="dlData('${c.id}',${i})">Descargar ${x.kind === 'segmento' ? 'segmento' : x.kind === 'fotograma' ? 'fotograma' : 'HTML'} capturado</button>` : ''}${x.tsa && x.tsa.tsr ? `<button class="ghost" onclick="dlTsr('${c.id}',${i})">Descargar sello .tsr</button>` : ''}${!ro && !realTsa(x.tsa) ? `<button class="ghost" onclick="restamp('${c.id}',${i})">Reintentar sello</button>` : ''}</div></div>`).join('')}</div>

  <div class="card step ${c.promos.length ? 'done' : ''}"><div class="fig">PASO 5.0</div><h2>Dónde se promocionó el enlace</h2>
  ${ro ? '' : `<div class="grid"><div><label>URL del posteo/mensaje</label><input id="pUrl" placeholder="https://x.com/... · t.me/... · discord.com/..."></div><div><label>Cuenta / canal</label><input id="pAcc" placeholder="@usuario o nombre del canal"></div><div><label>Alcance (seguidores/miembros)</label><input id="pReach" inputmode="numeric"></div></div><label>Captura del posteo (opcional, se hashea)</label><input id="pFile" type="file" accept="image/*"><div class="row" style="margin-top:8px"><button onclick="addPromo('${c.id}')">Agregar</button></div>`}
  ${c.promos.length ? `<div class="tbl"><table><tr><th>Red</th><th>Cuenta</th><th>Enlace</th><th>Alcance</th><th>Registrado</th></tr>${c.promos.map(p => `<tr><td><span class="pill info">${esc(p.platform)}</span></td><td>${esc(p.account || '—')}</td><td class="mono">${esc(p.url)}${p.sha256 ? `<div class="mut">captura ${esc(p.sha256.slice(0, 16))}…</div>` : ''}</td><td>${esc(p.reach || '—')}</td><td>${fmt(p.addedAt)}</td></tr>`).join('')}</table></div>` : ''}</div>

  <div class="card step ${c.expiry ? 'done' : ''}"><div class="fig">PASO 6.0</div><h2>Medida y vencimiento propuesto</h2>
  ${ro ? '' : `<button class="ghost" onclick="doExpiry('${c.id}')" ${a ? '' : 'disabled'}>${c.expiry ? 'Recalcular' : 'Proponer vencimiento'}</button>${a ? '' : ' <span class="small mut">(requiere análisis)</span>'}`}
  ${c.expiry ? `<p class="small">${esc(c.expiry.why)}</p><div class="tbl"><table><tr><th>Objetivo</th><th>Método</th><th>Vence</th></tr>${c.expiry.items.map((it, i) => `<tr><td>${esc(it.target)}${it.note ? `<div class="small mut">${esc(it.note)}</div>` : ''}</td><td>${esc(it.method)}</td><td>${it.until ? (ro ? fmt(it.until) : `<input type="date" value="${it.until.slice(0, 10)}" onchange="setUntil('${c.id}',${i},this.value)">`) : '—'}</td></tr>`).join('')}</table></div>` : ''}</div>

  <div class="card step ${c.seal ? (realTsa(c.seal.tsa) ? 'done' : 'warn') : ''}"><div class="fig">PASO 7.0</div><h2>Sellado del expediente</h2>
  ${c.seal ? `<div class="verdict ok">Expediente sellado. Hash SHA-256 del contenido:</div><div class="mono">${esc(c.seal.sha256)}</div>${tsaBox(c.seal.tsa, 'Sello del expediente')}
   <div class="row noprint" style="margin-top:8px">${c.seal.tsa && c.seal.tsa.tsr ? `<button class="ghost" onclick="dlSealTsr('${c.id}')">Descargar sello .tsr</button>` : ''}${!realTsa(c.seal.tsa) ? `<button class="ghost" onclick="restampSeal('${c.id}')">Reintentar sello</button>` : ''}<button class="ghost" onclick="reopen('${c.id}')">Nueva versión</button></div>
   ${verifyHint(c.seal.sha256, c.seal.tsa)}`
    : `<p class="small mut">Congela el expediente: calcula el SHA-256 de todo su contenido y lo sella con hora oficial. Cualquier cambio posterior se detecta en “Verificar”.</p><button class="ok" onclick="sealCase('${c.id}')">Sellar expediente</button>`}</div>
  ${await oracleCards(c)}
  <div class="row noprint"><button class="bad" onclick="delCase('${c.id}')">Eliminar</button></div>`;
}

/* --- Acciones de expediente --- */
async function stamp(hash) {
  try {
    const r = await fetch('/api/timestamp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sha256: hash }) });
    const j = await r.json(); if (!r.ok) return { error: (j.error || 'error') + (j.tried ? ` (${j.tried.join(' · ')})` : '') };
    return { tsa: j.tsa, tsaId: j.tsaId, genTime: j.genTime, imprintPresent: j.imprintPresent, nonce: j.nonce, tsr: j.tsr, status: j.status };
  } catch { return { error: 'sin conexión con la TSA' }; }
}
function realTsa(t) { return !!(t && t.genTime && !t.demo); }
async function stampFor(c, hash) {
  const t = await stamp(hash);
  return t.error && c.demo ? { tsa: 'Sello simulado (DEMO)', tsaId: 'demo', demo: true, genTime: new Date().toISOString(), imprintPresent: false, tsr: null, reason: t.error } : t;
}
window.runAnalysis = async (id) => {
  const c = getCase(id); if (!c || c.seal) return;
  const vi = $('#vidIn'); if (vi) c.videoUrl = vi.value.trim() || null;
  const st = $('#anStatus'); if (st) st.innerHTML = '<p><span class="spin"></span> Siguiendo la cadena de carga, resolviendo DNS, ASN y sitios en la misma IP… (hasta 30 s)</p>';
  const b = $('#anBtn'); if (b) b.disabled = true;
  try {
    const r = await fetch(`/api/analyze?url=${encodeURIComponent(c.target)}${c.videoUrl ? '&video=' + encodeURIComponent(c.videoUrl) : ''}`);
    const j = await r.json(); if (!r.ok) throw new Error(j.error || 'error');
    c.analysis = j; save();
    await audit('analisis_tecnico', c.id, `entrega=${j.deliveryHost || 'no detectada'} hash=${j.reportSha256}`);
    if (st) st.innerHTML = '<p><span class="spin"></span> Sellando informe técnico…</p>';
    c.analysisTsa = await stampFor(c, j.reportSha256); save();
    if (c.watermark) c.watermark = await checkWatermark(c, c.watermark.payload);
    save(); toast('Análisis completo');
  } catch (e) { toast('Falló el análisis: ' + e.message); }
  route();
};
function b64ToBytes(b64) { const s = atob(b64); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
window.autoCapture = async (id) => {
  const c = getCase(id); if (!c || c.seal) return false;
  const st = $('#capStatus'); const say = (t) => { if (st) st.innerHTML = `<p><span class="spin"></span> ${t}</p>`; };
  say(`Descargando ${esc(hostOf(c.target))} tal como la entrega el servidor…`);
  try {
    const r = await fetch('/api/capture?url=' + encodeURIComponent(c.target)); const j = await r.json();
    if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
    const bytes = b64ToBytes(j.b64); const hash = await sha256Hex(bytes);
    if (hash !== j.sha256) throw new Error('el hash recalculado no coincide con el del servidor');
    if (c.captures.some(x => x.sha256 === hash)) { toast('La página no cambió desde la última captura'); return true; }
    const host = hostOf(j.finalUrl) || 'pagina';
    const cap = { name: `pagina_${host}_${j.fetchedAt.replace(/[:.]/g, '-')}.html`, size: j.bytes, type: (j.contentType || 'text/html') + ' · captura automática', auto: true, lastModified: j.fetchedAt, addedAt: new Date().toISOString(), sha256: hash, thumb: null,
      source: { url: c.target, finalUrl: j.finalUrl, httpStatus: j.status, hops: j.hops, headers: j.headers, title: j.title, fetchedAt: j.fetchedAt, truncated: j.truncated, capturer: j.capturer } };
    if (j.bytes <= 300000) cap.data64 = j.b64;
    say('Pidiendo sello de tiempo RFC 3161 para la captura…');
    cap.tsa = await stampFor(c, hash);
    c.captures.push(cap);
    saveCapped(cap);
    await audit('captura_agregada', id, `${cap.name} (automática, HTTP ${j.status}) sha256=${hash}`);
    return true;
  } catch (e) { toast('No se pudo capturar la página: ' + e.message); return false; }
};
window.autoCaptureBtn = async (id) => { await autoCapture(id); route(); };
window.autoVerify = async (id, sealAfter) => {
  await runAnalysis(id);
  const c = getCase(id); if (!c || c.seal) return;
  if (manifestOf(c)) await streamCapture(id);
  await autoCapture(id);
  if (!c.expiry) { c.expiry = proposeExpiry(c); save(); await audit('vencimiento_propuesto', id, c.expiry.why); }
  if (sealAfter) await sealNow(c);
  route(); toast(`Verificación automática terminada: solidez ${score(c).pct}%`);
};
window.dlData = (id, i) => { const c = getCase(id), x = c.captures[i]; const b = x.data64 || x.html64; if (!b) return toast('El archivo era muy grande para guardarlo en el dispositivo; quedó registrado su hash'); download(x.name, new Blob([b64ToBytes(b)], { type: (x.type || '').split(' ')[0] || 'application/octet-stream' })); };
function saveCapped(cap) { try { save(); } catch { delete cap.data64; try { save(); } catch { toast('El almacenamiento del navegador está lleno'); } } }
function bytesToB64(u) { let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); }

/* ===== Verificación del stream de fútbol ===== */
let muxLoading = null;
function loadMux() {
  if (window.muxjs) return Promise.resolve();
  return muxLoading || (muxLoading = new Promise((ok, ko) => { const s = document.createElement('script'); s.src = 'https://cdn.jsdelivr.net/npm/mux.js@7.0.3/dist/mux.min.js'; s.onload = ok; s.onerror = () => { muxLoading = null; ko(new Error('no cargó mux.js')); }; document.head.appendChild(s); }));
}
// Saca un fotograma real de un segmento MPEG-TS: lo pasa a MP4 fragmentado (mux.js) y lo dibuja en un canvas.
async function frameFromTs(bytes) {
  await loadMux();
  const tm = new muxjs.mp4.Transmuxer({ remux: true }); const parts = []; let init = null;
  tm.on('data', s => { if (!init) init = s.initSegment; parts.push(s.data); });
  tm.push(bytes); tm.flush();
  if (!init) throw new Error('el segmento no tiene video decodificable');
  const v = document.createElement('video'); v.muted = true; v.playsInline = true; v.src = URL.createObjectURL(new Blob([init, ...parts], { type: 'video/mp4' }));
  try {
    await new Promise((ok, ko) => { v.onloadeddata = ok; v.onerror = () => ko(new Error('el navegador no pudo decodificar el video')); setTimeout(() => ko(new Error('tiempo agotado al decodificar')), 10000); });
    v.currentTime = Math.min(1, (v.duration || 0) / 2);
    await new Promise(ok => { v.onseeked = ok; setTimeout(ok, 3000); });
    const cv = document.createElement('canvas'); cv.width = v.videoWidth; cv.height = v.videoHeight; cv.getContext('2d').drawImage(v, 0, 0);
    const blob = await new Promise(ok => cv.toBlob(ok, 'image/png'));
    return { blob, width: v.videoWidth, height: v.videoHeight, at: v.currentTime };
  } finally { URL.revokeObjectURL(v.src); }
}
function manifestOf(c) {
  const p = c.analysis && (c.analysis.video || []).find(x => x.type && x.type.startsWith('HLS'));
  if (p) return { url: p.url, ref: p.referer || c.target };
  if (c.videoUrl && /\.m3u8/i.test(c.videoUrl)) return { url: c.videoUrl, ref: c.target };
  return null;
}
window.streamCapture = async (id) => {
  const c = getCase(id); if (!c || c.seal) return false;
  const mf = manifestOf(c);
  if (!mf) { toast('No hay manifiesto .m3u8: corré el análisis o pegá la URL del video'); return false; }
  const st = $('#strStatus'); const say = (t) => { if (st) st.innerHTML = `<p><span class="spin"></span> ${t}</p>`; else toast(t); };
  say('Leyendo el manifiesto y comprobando que el stream esté en vivo…');
  try {
    const r = await fetch(`/api/stream-capture?url=${encodeURIComponent(mf.url)}&ref=${encodeURIComponent(mf.ref)}`); const j = await r.json();
    if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
    const sample = j.sample && b64ToBytes(j.sample.b64);
    if (sample && await sha256Hex(sample) !== j.sample.sha256) throw new Error('el hash recalculado del segmento no coincide con el del servidor');
    c.stream = { manifest: j.manifest, referer: j.referer, variant: j.variant, mediaPlaylist: j.mediaPlaylist, mediaPlaylistSha256: j.mediaPlaylistSha256, live: j.live, encrypted: j.encrypted, fmp4: j.fmp4, capturedAt: j.finishedAt, segments: j.segments.map(s => ({ seq: s.seq, sha256: s.sha256 || null, bytes: s.bytes || 0, status: s.status || null, error: s.error || null })), frame: null, frameError: null };
    let n = 0;
    for (const s of j.segments.filter(s => s.sha256 && s.status < 400)) {
      if (c.captures.some(x => x.sha256 === s.sha256)) continue;
      say(`Sellando el segmento ${esc(s.seq)} (RFC 3161)…`);
      const cap = { name: `segmento_${hostOf(s.url)}_${s.seq}.ts`, size: s.bytes, type: (s.contentType || 'video/MP2T') + ' · segmento del stream', auto: true, kind: 'segmento', lastModified: s.fetchedAt, addedAt: new Date().toISOString(), sha256: s.sha256, thumb: null,
        source: { url: s.url, finalUrl: s.finalUrl, httpStatus: s.status, fetchedAt: s.fetchedAt, seq: s.seq, duration: s.duration, programDateTime: s.programDateTime, server: s.server, truncated: s.truncated, manifest: j.mediaPlaylist, live: j.live.isLive, capturer: j.capturer } };
      if (j.sample && j.sample.sha256 === s.sha256 && s.bytes <= 300000) cap.data64 = j.sample.b64;
      cap.tsa = await stampFor(c, s.sha256); c.captures.push(cap); saveCapped(cap); n++;
      await audit('captura_agregada', id, `${cap.name} (segmento del stream, ${j.live.isLive ? 'en vivo' : 'no en vivo'}) sha256=${s.sha256}`);
    }
    if (sample && !j.encrypted && !j.fmp4) {
      say('Sacando un fotograma del partido para el detector de marca de agua…');
      try {
        const f = await frameFromTs(sample);
        const bytes = new Uint8Array(await f.blob.arrayBuffer()); const hash = await sha256Hex(bytes);
        const file = new File([f.blob], `fotograma_${j.sample.seq}.png`, { type: 'image/png' });
        const cap = { name: file.name, size: bytes.length, type: 'image/png · fotograma del stream', auto: true, kind: 'fotograma', lastModified: j.finishedAt, addedAt: new Date().toISOString(), sha256: hash, thumb: await thumbOf(file),
          source: { fromSegmentSha256: j.sample.sha256, seq: j.sample.seq, width: f.width, height: f.height, offsetS: f.at, manifest: j.mediaPlaylist, capturer: 'navegador (mux.js + canvas)' } };
        if (bytes.length <= 400000) cap.data64 = bytesToB64(bytes);
        say('Sellando el fotograma (RFC 3161)…');
        cap.tsa = await stampFor(c, hash); c.captures.push(cap); saveCapped(cap); n++;
        c.stream.frame = { sha256: hash, width: f.width, height: f.height };
        await audit('captura_agregada', id, `${cap.name} (fotograma del segmento ${j.sample.seq}) sha256=${hash}`);
      } catch (e) { c.stream.frameError = e.message; }
    } else c.stream.frameError = j.encrypted ? `segmentos cifrados (${j.encrypted})` : j.fmp4 ? 'segmentos fMP4 (sin soporte todavía)' : 'segmento demasiado grande para descargarlo al navegador';
    save(); await audit('stream_capturado', id, `${j.mediaPlaylist} vivo=${j.live.isLive} segmentos=${j.segments.length} capturas=${n}`);
    return true;
  } catch (e) { toast('No se pudo capturar el stream: ' + e.message); return false; }
};
window.streamCaptureBtn = async (id) => { await streamCapture(id); route(); };

const norm = (s) => (s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ');
const GENERIC = new Set(['club', 'atletico', 'deportivo', 'central', 'union', 'independiente', 'estudiantes', 'gimnasia', 'san', 'de', 'cd', 'ca', 'el']);
function teamAliases(name) {
  const n = norm(name).replace(/\s+/g, ' ').trim(); const w = n.split(' '); const out = new Set([n]);
  if (w[0] && !GENERIC.has(w[0]) && w[0].length >= 4) out.add(w[0]);
  if (/newell/.test(n)) out.add('newells');
  if (/^(gimnasia|estudiantes)/.test(n) && /la plata/.test(n)) out.add(w[0] + ' lp');
  return [...out];
}
function teamIn(text, name) { return teamAliases(name).some(a => new RegExp('(^| )' + a.replace(/ /g, ' +') + '( |$)').test(text)); }
function detectMatch(c) {
  const s = c.analysis && c.analysis.signals; if (!s) return null;
  const text = ' ' + norm(s.title + ' ' + s.text).replace(/\s+/g, ' ') + ' ';
  const mine = { home: teamIn(text, c.match.home), away: teamIn(text, c.match.away) };
  const now = new Date(c.analysis.startedAt || Date.now()).getTime();
  const other = allMatches().filter(m => m.id !== c.match.id && teamIn(text, m.home) && teamIn(text, m.away))
    .sort((a, b) => Math.abs(new Date(a.kickoff) - now) - Math.abs(new Date(b.kickoff) - now))[0] || null;
  return { mine, other };
}
function authorizedHost(h) { for (const l of DB.licensees) for (const d of l.domains) if (h === d || h.endsWith('.' + d)) return l; return null; }
function streamChecks(c) {
  const a = c.analysis, s = a && a.signals, st = c.stream; const out = [];
  const add = (ok, t, d) => out.push({ ok, t, d });
  if (!a) return out;
  const players = (s && s.players) || [];
  add(players.length || manifestOf(c) ? true : false, 'Reproductor de video en la página', players.length ? players.join(', ') + (manifestOf(c) ? ' · manifiesto HLS encontrado' : '') : manifestOf(c) ? 'manifiesto HLS encontrado' : 'no se encontró reproductor ni stream');
  const kw = (s && s.keywords) || []; const dm = detectMatch(c);
  add(kw.some(k => k !== 'en vivo') || (dm && (dm.mine.home || dm.mine.away)) ? true : false, 'Contenido de fútbol', kw.length ? kw.join(', ') : 'la página no menciona fútbol, partidos ni ligas');
  if (dm) {
    if (dm.mine.home && dm.mine.away) add(true, 'Nombra el partido del expediente', matchName(c.match));
    else if (dm.other) add(false, 'Nombra otro partido', `${matchName(dm.other)} · ${fmtD(dm.other.kickoff)}`);
    else add(null, 'Partido', dm.mine.home || dm.mine.away ? `nombra a ${dm.mine.home ? c.match.home : c.match.away}` : 'la página no nombra los equipos');
  }
  const ch = (s && s.channels) || [];
  add(ch.length ? true : null, 'Canal anunciado', ch.length ? ch.map(x => x.name + (x.lic ? ` (${x.lic})` : '')).join(', ') : 'no menciona canal');
  const auth = (a.hosts || []).filter(h => h.roles.some(r => r === 'pagina' || r === 'embed')).map(h => [h.host, authorizedHost(h.host)]).filter(x => x[1]);
  add(auth.length ? false : true, auth.length ? 'Dominio de un licenciatario autorizado' : 'La página no es de un licenciatario', auth.length ? auth.map(([h, l]) => `${h} → ${l.name}`).join(', ') + ': distribución autorizada, no corresponde expediente' : 'ni la página ni los reproductores embebidos son dominios autorizados');
  if (!st) add(null, 'Stream en vivo', manifestOf(c) ? 'todavía no se capturó el stream' : 'sin manifiesto .m3u8');
  else {
    add(st.live.isLive ? true : false, st.live.isLive ? 'Stream en vivo' : 'El stream no está en vivo', st.live.isLive ? `la secuencia avanzó de ${st.live.firstSequence} a ${st.live.secondSequence} entre ${fmt(st.live.firstAt)} y ${fmt(st.live.secondAt)}` : st.live.endList ? 'el manifiesto está cerrado (grabación / VOD)' : 'la secuencia no avanzó');
    const ko = new Date(c.match.kickoff).getTime(), t = new Date(st.capturedAt).getTime();
    add(t >= ko - 30 * 60e3 && t <= ko + 3 * 3600e3 ? true : null, 'Capturado durante el partido', `captura ${fmt(st.capturedAt)} · inicio ${fmt(c.match.kickoff)}`);
    const segs = c.captures.filter(x => x.kind === 'segmento' && x.source && x.source.manifest === st.mediaPlaylist);
    add(segs.length && segs.every(x => realTsa(x.tsa)) ? true : segs.length ? null : false, 'Segmentos del stream con SHA-256 y sello RFC 3161', segs.length ? `${segs.length} segmento(s)` : 'no se pudieron bajar segmentos');
    add(st.frame ? true : false, 'Fotograma para el detector de marca de agua', st.frame ? `${st.frame.width}×${st.frame.height}, SHA-256 ${st.frame.sha256.slice(0, 16)}…` : st.frameError || 'sin fotograma');
  }
  return out;
}
function streamVerdict(c, ch) {
  const get = (t) => ch.find(x => x.t === t);
  if (ch.some(x => x.t === 'Dominio de un licenciatario autorizado')) return ['bad', 'Es un dominio autorizado: no corresponde expediente'];
  const player = get('Reproductor de video en la página'), foot = get('Contenido de fútbol'), live = get('Stream en vivo');
  if (player && player.ok && foot && foot.ok && live && live.ok) return ['ok', 'Streaming de fútbol en vivo verificado' + (ch.some(x => x.t === 'Nombra otro partido') ? ' (pero nombra otro partido)' : '')];
  if (player && player.ok && foot && foot.ok) return ['warn', c.stream ? 'Streaming de fútbol, pero el stream no está en vivo' : 'Parece streaming de fútbol: falta capturar el stream'];
  return ['bad', 'No se confirmó que sea un streaming de fútbol'];
}
function streamCard(c, ro) {
  if (!c.analysis) return `<div class="card step"><div class="fig">PASO 0.0</div><h2>Verificación del stream de fútbol</h2><p class="small mut">Corré el análisis (PASO 2.0) o usá “Crear y verificar”: se detecta el reproductor, el partido y el canal, se comprueba que el stream esté en vivo y se capturan segmentos y un fotograma con hash y sello.</p></div>`;
  const ch = streamChecks(c); const [v, txt] = streamVerdict(c, ch); const dm = detectMatch(c);
  return `<div class="card step ${v === 'ok' ? 'done' : v}"><div class="fig">PASO 0.0</div><h2>Verificación del stream de fútbol</h2>
  <div class="verdict ${v}">${v === 'ok' ? '✔ ' : v === 'bad' ? '✖ ' : ''}${esc(txt)}</div>
  <ul class="check small">${ch.map(x => `<li>${x.ok === true ? '<i class="ck y"></i>' : x.ok === false ? '<i class="ck n"></i>' : '<i class="ck w"></i>'} <span><b>${esc(x.t)}</b> · ${esc(x.d)}</span></li>`).join('')}</ul>
  ${c.stream ? `<div class="small mut">Manifiesto ${esc(c.stream.mediaPlaylist)}${c.stream.variant ? ` · variante ${esc(c.stream.variant.resolution || '')} ${Math.round((c.stream.variant.bandwidth || 0) / 1000)} kbps` : ''} · SHA-256 del manifiesto ${esc((c.stream.mediaPlaylistSha256 || '').slice(0, 16))}…</div>` : ''}
  ${!ro && dm && dm.other && !(dm.mine.home && dm.mine.away) ? `<button class="ghost" onclick="setCaseMatch('${c.id}','${esc(dm.other.id)}')">Cambiar al partido detectado: ${esc(matchName(dm.other))}</button>` : ''}
  ${!ro && manifestOf(c) ? `<div class="row noprint" style="margin-top:8px"><button onclick="streamCaptureBtn('${c.id}')">${c.stream ? 'Volver a capturar el stream' : 'Capturar el stream (segmentos + fotograma)'}</button></div><div id="strStatus"></div>` : ''}</div>`;
}
window.setCaseMatch = async (id, mid) => {
  const c = getCase(id), m = matchById(mid); if (!c || c.seal || !m) return;
  const prev = matchName(c.match);
  c.match = { id: m.id, home: m.home, away: m.away, kickoff: m.kickoff, round: m.round || null, venue: m.venue || null, league: m.league || 'Liga Profesional de Fútbol' };
  if (c.watermark) c.watermark = await checkWatermark(c, c.watermark.payload);
  save(); await audit('partido_cambiado', id, `${prev} → ${matchName(m)}`); route();
};
window.doWatermark = async (id) => {
  const c = getCase(id); const p = $('#wmIn').value;
  c.watermark = await checkWatermark(c, p); save();
  await audit('marca_verificada', id, `${c.watermark.payload} → ${c.watermark.verdict}`); route();
};
async function thumbOf(file) {
  if (!file.type.startsWith('image/')) return null;
  try {
    const bmp = await createImageBitmap(file); const k = 220 / Math.max(bmp.width, bmp.height);
    const cv = document.createElement('canvas'); cv.width = bmp.width * k; cv.height = bmp.height * k; cv.getContext('2d').drawImage(bmp, 0, 0, cv.width, cv.height);
    return cv.toDataURL('image/jpeg', 0.6);
  } catch { return null; }
}
window.addCaptures = async (id, files) => {
  const c = getCase(id); const st = $('#capStatus');
  for (const f of files) {
    st.innerHTML = `<p><span class="spin"></span> Calculando SHA-256 de ${esc(f.name)}…</p>`;
    const hash = await sha256File(f, (k) => { st.innerHTML = `<p><span class="spin"></span> Calculando SHA-256 de ${esc(f.name)}… ${Math.round(k * 100)} %</p>`; });
    if (c.captures.some(x => x.sha256 === hash)) { toast('Captura repetida'); continue; }
    const cap = { name: f.name, size: f.size, type: f.type || 'desconocido', lastModified: new Date(f.lastModified).toISOString(), addedAt: new Date().toISOString(), sha256: hash, thumb: await thumbOf(f) };
    st.innerHTML = `<p><span class="spin"></span> Pidiendo sello de tiempo para ${esc(f.name)}…</p>`;
    cap.tsa = await stampFor(c, hash);
    c.captures.push(cap); save();
    await audit('captura_agregada', id, `${f.name} sha256=${hash}`);
  }
  route();
};
window.restampSeal = async (id) => {
  const c = getCase(id); if (!c.seal) return;
  toast('Pidiendo sello de tiempo…'); c.seal.tsa = await stampFor(c, c.seal.sha256); save();
  if (realTsa(c.seal.tsa)) await audit('expediente_sellado', id, `v${c.version} sha256=${c.seal.sha256} (sello reintentado)`);
  route();
};
window.restampReport = async (id) => { const c = getCase(id); c.analysisTsa = await stampFor(c, c.analysis.reportSha256); save(); route(); };
window.restamp = async (id, i) => { const c = getCase(id); c.captures[i].tsa = await stampFor(c, c.captures[i].sha256); save(); route(); };
window.dlTsr = (id, i) => { const c = getCase(id), x = c.captures[i]; if (!x.tsa || !x.tsa.tsr) return toast('Este sello no tiene .tsr (simulado o fallido)'); download(`${c.num}_${x.sha256.slice(0, 12)}.tsr`, b64ToBlob(x.tsa.tsr, 'application/timestamp-reply')); };
window.dlSealTsr = (id) => { const c = getCase(id); if (!c.seal.tsa || !c.seal.tsa.tsr) return toast('Este sello no tiene .tsr (simulado o fallido)'); download(`${c.num}_v${c.version}_sello.tsr`, b64ToBlob(c.seal.tsa.tsr, 'application/timestamp-reply')); };
function platformOf(u) {
  const h = hostOf(u);
  if (/(^|\.)(x|twitter)\.com$/.test(h)) return 'X';
  if (/discord\.(gg|com)$/.test(h)) return 'Discord';
  if (/(^|\.)(t\.me|telegram\.(me|org))$/.test(h) || h === 't.me') return 'Telegram';
  if (/facebook|fb\.com/.test(h)) return 'Facebook'; if (/instagram/.test(h)) return 'Instagram'; if (/tiktok/.test(h)) return 'TikTok';
  if (/whatsapp|wa\.me/.test(h)) return 'WhatsApp'; if (/reddit/.test(h)) return 'Reddit'; if (/youtube|youtu\.be/.test(h)) return 'YouTube';
  return 'Otro';
}
window.addPromo = async (id) => {
  const c = getCase(id); const url = $('#pUrl').value.trim(); if (!hostOf(url)) return toast('URL inválida');
  const p = { platform: platformOf(url), url, account: $('#pAcc').value.trim(), reach: $('#pReach').value.trim(), addedAt: new Date().toISOString() };
  const f = $('#pFile').files[0];
  if (f) { p.sha256 = await sha256File(f); p.file = f.name; p.tsa = await stampFor(c, p.sha256); }
  c.promos.push(p); save(); await audit('promocion_agregada', id, `${p.platform} ${url}`); route();
};
window.doExpiry = async (id) => { const c = getCase(id); c.expiry = proposeExpiry(c); save(); await audit('vencimiento_propuesto', id, c.expiry.why); route(); };
window.setUntil = async (id, i, v) => { const c = getCase(id); c.expiry.items[i].until = new Date(v + 'T23:59:00-03:00').toISOString(); c.expiry.edited = true; save(); await audit('vencimiento_editado', id, `${c.expiry.items[i].target} → ${v}`); };
function sealPayload(c) { const { seal, estado, signature, annexOf, rejection, remoteId, ...rest } = c; const r = JSON.parse(JSON.stringify(rest)); r.captures.forEach(x => { delete x.thumb; delete x.html64; delete x.data64; }); return r; }
async function sealNow(c) {
  const hash = await sha256Hex(stable(sealPayload(c)));
  toast('Sellando…');
  c.seal = { sha256: hash, sealedAt: new Date().toISOString(), tsa: await stampFor(c, hash) }; save();
  await audit('expediente_sellado', c.id, `v${c.version} sha256=${hash}`);
}
window.sealCase = async (id) => {
  const c = getCase(id);
  if (score(c).pct < 50 && !confirm('El expediente tiene solidez baja. ¿Sellar igual?')) return;
  await sealNow(c); route();
};
window.reopen = async (id) => {
  const c = getCase(id); if (!confirm('Se abre una nueva versión editable. El sello anterior queda en el historial.')) return;
  c.history = c.history || []; c.history.push({ version: c.version, seal: { sha256: c.seal.sha256, sealedAt: c.seal.sealedAt, genTime: c.seal.tsa && c.seal.tsa.genTime } });
  c.version++; c.seal = null; save(); await audit('nueva_version', id, `v${c.version}`); route();
};
window.delCase = async (id) => { if (!confirm('¿Eliminar expediente? Queda registrado en auditoría.')) return; const c = getCase(id); DB.cases = DB.cases.filter(x => x.id !== id); save(); await audit('expediente_eliminado', id, c.num); go('#/expedientes'); };
const ESTADO_TXT = { en_cola_juez: 'En cola del juez', revision_humana: 'Revisión humana', firmado: 'Firmado por el juez', rechazado: 'Rechazado', anexado: 'Anexado' };
async function vInforme(_, qs) {
  const sel = qs.get('match') || '';
  const ms = allMatches().filter(m => DB.cases.some(c => c.match.id === m.id) || m.source === 'manual');
  const cs = DB.cases.filter(c => !sel || c.match.id === sel);
  const orders = (DB.orders || []).filter(o => cs.some(c => c.id === o.caseId));
  const claims = (DB.claims || []).filter(r => r.orderId ? orders.some(o => o.id === r.orderId) : !sel);
  const au = await verifyAudit();
  const ahora = new Date().toISOString();
  const resumen = { generado: ahora, partido: sel || 'todos', expedientes: cs.map(c => [c.num, c.version, c.target, c.estado, c.seal ? c.seal.sha256 : null, c.analysis ? c.analysis.reportSha256 : null]), ordenes: orders.map(o => [o.num, o.objetivo, o.estado]), reclamos: claims.map(r => [r.dominio, r.estado, r.orderId]), auditoria: DB.audit.length ? DB.audit[DB.audit.length - 1].hash : null };
  const hash = await sha256Hex(stable(resumen));
  const fila = (k, v) => v ? `<tr><th>${esc(k)}</th><td>${v}</td></tr>` : '';
  const card = (c) => {
    const a = c.analysis, dh = a && a.hosts.find(h => h.host === a.deliveryHost), ip = dh && dh.ips && dh.ips[0];
    const wm = c.watermark, sg = c.signature, cons = c.consensus;
    return `<div class="card"><div class="row sp"><h2>${esc(c.num)} <span class="small mut">v${c.version}</span></h2><span class="pill ${c.estado === 'firmado' ? 'ok' : 'warn'}">${esc(ESTADO_TXT[c.estado] || (c.seal ? 'Sellado' : 'Borrador'))}</span></div>
    <table>${fila('Partido', esc(matchName(c.match)) + ' · ' + fmt(c.match.kickoff))}${fila('Enlace pirata', `<span class="mono">${esc(c.target)}</span>`)}${fila('Detectado', fmt(c.createdAt) + (c.notes ? ' · ' + esc(c.notes) : ''))}
    ${fila('Análisis técnico', a ? `${fmt(a.finishedAt || a.startedAt)} · HTTP ${esc((a.chain[0] || {}).status || '—')} · huella <span class="mono">${esc((a.reportSha256 || '').slice(0, 16))}…</span>` : '<span class="mut">sin análisis técnico</span>')}
    ${fila('Hosts e IP', a ? a.hosts.map(h => `<span class="mono">${esc(h.host)}</span> (${esc(h.roles.join(', '))}) · ${esc((h.a || []).join(', '))}${h.ips && h.ips[0] ? ` · AS${esc(h.ips[0].asn)} ${esc(h.ips[0].holder || '')}` : ''}`).join('<br>') : '')}
    ${fila('Video entregado por', dh ? `<span class="mono">${esc(dh.host)}</span> · ${esc((dh.a || []).join(', '))}${ip ? ` · AS${esc(ip.asn)} ${esc(ip.holder || '')} (${esc(ip.country || '')})` : ''}` : a ? '<span class="mut">no se detectó video en la página</span>' : '')}
    ${fila('Riesgo colateral', dh && dh.collateral ? `${esc(dh.collateral.level)} → ${dh.collateral.recommendation === 'bloquear_dominio' ? 'bloquear por dominio' : 'bloquear por IP y dominio'}. ${esc(dh.collateral.reason || '')}` : '')}
    ${fila('Marca de agua', wm ? `${wm.verdict === 'ok' ? '✔ señal oficial redistribuida sin autorización' : '✖ no valida'} · <span class="mono">${esc(wm.payload)}</span>${wm.licensee ? ' · ' + esc(wm.licensee.name) : ''}` : '<span class="mut">sin verificar</span>')}
    ${fila('Oráculo', cons ? `${cons.ok ? '✔ consenso' : '✖ sin consenso'} · ${cons.checks.map(x => (x.ok ? '✔ ' : '✖ ') + esc(x.k)).join(' · ')}` : '<span class="mut">no corrido</span>')}
    ${fila('Promoción', (c.promos || []).map(p => `${esc(p.platform)} ${esc(p.account || '')}`).join(' · '))}
    ${fila('Capturas', (c.captures || []).length ? `${c.captures.length} con SHA-256` : '')}
    ${fila('Sello', c.seal ? `<span class="mono">sha256 ${esc(c.seal.sha256)}</span>${c.seal.tsa && c.seal.tsa.genTime ? ' · TSA ' + fmt(c.seal.tsa.genTime) : ''}` : '<span class="mut">sin sellar</span>')}
    ${fila('Decisión judicial', sg ? `Firmado por ${esc(sg.juez)} (${esc(sg.juzgado)}) · ${fmt(sg.ts)} · ${esc(sg.alg)}` : c.rejection ? `Rechazado por ${esc(c.rejection.juez)}: ${esc(c.rejection.why)}` : '')}
    ${fila('Vencimiento propuesto', c.expiry ? `${esc(c.expiry.why)}<br>${c.expiry.items.map(it => `${esc(it.target)} · ${esc(it.method)} · hasta ${it.until ? fmt(it.until) : '—'}`).join('<br>')}` : '')}</table></div>`;
  };
  return `${hero('Informe general', 'de todo lo relevado: expedientes, servidores de video, oráculo, decisión judicial, órdenes y auditoría.')}
  <div class="card noprint"><div class="row"><select id="iMatch" onchange="go('#/informe?match='+encodeURIComponent(this.value))"><option value="">Todos los partidos</option>${ms.map(m => `<option value="${esc(m.id)}" ${m.id === sel ? 'selected' : ''}>${esc(matchName(m))} · ${fmtD(m.kickoff)}</option>`).join('')}</select>
  <button onclick="downloadPdf('informe_${sel ? 'partido' : 'general'}_${ahora.slice(0, 10)}')" ${cs.length ? '' : 'disabled'}>Descargar informe PDF</button></div>
  ${cs.length ? '' : '<p class="mut">Todavía no hay expedientes. <a href="#/partidos">Agregá tu partido</a> y después pegá el enlace en <a href="#/nuevo">Nuevo expediente</a>.</p>'}</div>
  <div class="card"><table>${fila('Generado', fmt(ahora))}${fila('Alcance', sel ? esc(matchName(matchById(sel))) : 'Todos los partidos')}${fila('Huella del informe', `<span class="mono">sha256 ${hash}</span>`)}</table>
  <div class="grid" style="margin-top:10px"><div class="kpi"><b>${cs.length}</b><span>Expedientes</span></div><div class="kpi"><b>${cs.filter(c => c.seal).length}</b><span>Sellados</span></div><div class="kpi"><b>${cs.filter(c => c.estado === 'firmado').length}</b><span>Firmados</span></div><div class="kpi"><b>${orders.length}</b><span>Órdenes</span></div><div class="kpi"><b>${claims.length}</b><span>Reclamos</span></div></div></div>
  ${cs.map(card).join('')}
  ${orders.length ? `<div class="card"><h2>Órdenes de bloqueo</h2><table><tr><th>Orden</th><th>Expediente</th><th>Objetivo</th><th>Tipo</th><th>Hasta</th><th>Estado</th></tr>${orders.map(o => `<tr><td>${esc(o.num)}</td><td>${esc(o.caseNum || '')}</td><td class="mono">${esc(o.objetivo)}</td><td>${esc(o.tipo)}</td><td>${o.hasta ? fmt(o.hasta) : '—'}</td><td>${esc(o.estado)}</td></tr>`).join('')}</table></div>` : ''}
  ${claims.length ? `<div class="card"><h2>Reclamos</h2><table><tr><th>Dominio</th><th>Motivo</th><th>Fecha</th><th>Estado</th></tr>${claims.map(r => `<tr><td class="mono">${esc(r.dominio)}</td><td>${esc(r.motivo)}</td><td>${fmt(r.at)}</td><td>${esc(r.estado)}</td></tr>`).join('')}</table></div>` : ''}
  <div class="card"><h2>Auditoría</h2><div class="verdict ${au.ok ? 'ok' : 'bad'}">${au.ok ? `✔ Cadena íntegra: ${au.n} registros encadenados por SHA-256` : `✖ ${esc(au.why)} en el registro ${au.at}`}</div>
  <table>${DB.audit.filter(e => !sel || !e.caseId || cs.some(c => c.id === e.caseId)).slice(-40).map(e => `<tr><td>${fmt(e.ts)}</td><td>${esc(e.action)}</td><td class="small">${esc(e.detail)}</td></tr>`).join('')}</table></div>`;
}
window.downloadPdf = async (nombre) => {
  if (typeof html2pdf === 'undefined') return window.print();
  toast('Generando PDF…');
  document.body.classList.add('pdf');
  let blob;
  try {
    blob = await html2pdf().set({ margin: 10, image: { type: 'jpeg', quality: 0.95 },
      html2canvas: { scale: 2, backgroundColor: '#ffffff', useCORS: true }, jsPDF: { unit: 'mm', format: 'a4' },
      pagebreak: { mode: ['css', 'legacy'], avoid: '.card' } }).from($('#app')).outputPdf('blob');
  } catch (e) { toast('No se pudo generar el PDF: ' + e.message); return; }
  finally { document.body.classList.remove('pdf'); }
  if (window._pdf) URL.revokeObjectURL(window._pdf.url);
  const file = nombre + '.pdf', url = URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
  const a = document.createElement('a'); a.href = url; a.download = file; document.body.appendChild(a); a.click(); a.remove();
  let box = $('#pdfBox'); if (!box) { box = document.createElement('div'); box.id = 'pdfBox'; document.body.appendChild(box); }
  box.innerHTML = `<b>Informe listo</b><span class="small">${esc(file)}</span><div class="row"><a class="btn" href="${url}" download="${esc(file)}">Descargar</a><a class="btn" href="${url}" target="_blank" rel="noopener">Abrir</a>${navigator.canShare ? '<button onclick="sharePdf()">Compartir</button>' : ''}<button class="ghost" onclick="closePdf()">Cerrar</button></div>`;
  window._pdf = { blob, file, url };
  await audit('informe_pdf', null, nombre);
};
window.closePdf = () => { $('#pdfBox')?.remove(); if (window._pdf) URL.revokeObjectURL(window._pdf.url); window._pdf = null; };
window.sharePdf = async () => {
  const f = new File([window._pdf.blob], window._pdf.file, { type: 'application/pdf' });
  if (navigator.canShare && navigator.canShare({ files: [f] })) { try { await navigator.share({ files: [f], title: window._pdf.file }); } catch {} }
  else toast('Este navegador no permite compartir archivos: usá «Abrir»');
};
window.exportCase = (id) => { const c = getCase(id); download(`${c.num}_v${c.version}.json`, JSON.stringify({ format: 'expedientes-futbol/1', exportedAt: new Date().toISOString(), case: c, audit: DB.audit.filter(e => e.caseId === id) }, null, 1)); };
window.exportAll = () => download(`expedientes_${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify({ format: 'expedientes-futbol-db/1', exportedAt: new Date().toISOString(), db: DB }, null, 1));
window.importAll = async (f) => {
  if (!f) return; try {
    const j = JSON.parse(await f.text());
    if (j.db) { if (!confirm('Reemplazar todos los datos por el archivo importado?')) return; DB = j.db; save(); await audit('base_importada', null, f.name); }
    else if (j.case) { if (!getCase(j.case.id)) DB.cases.push(j.case); save(); await audit('expediente_importado', j.case.id, j.case.num); }
    toast('Importado'); route();
  } catch { toast('Archivo inválido'); }
};

/* --- Base de conocimiento --- */
async function vConocimiento() {
  const k = knowledge();
  const rows = (map, cols) => [...map.values()].sort((a, b) => b.cases.size - a.cases.size).map(e => `<tr><td class="mono"><a href="#/expedientes?q=${encodeURIComponent(e.key)}">${esc(e.key)}</a></td>${cols(e)}<td><span class="pill ${e.cases.size > 1 ? 'bad' : ''}">${e.cases.size}</span></td><td>${e.matches.size}</td><td>${fmtD(e.last)}</td></tr>`).join('');
  return `${hero('Base de conocimiento', 'que aprende con cada caso y detecta reincidencia.')}<p class="small mut">Se alimenta con cada expediente: dominios, IPs y proveedores relevados. Los nuevos análisis se cruzan contra esta base para detectar reincidencia y endurecer el vencimiento propuesto.</p>
  <div class="card"><h2>Proveedores (ASN)</h2><div class="tbl"><table><tr><th>ASN</th><th>Titular</th><th>Tipo</th><th>Exp.</th><th>Partidos</th><th>Último</th></tr>${rows(k.asn, e => `<td>${esc(e.holder || '')}</td><td>${esc(e.kind || '')}</td>`) || '<tr><td colspan=6 class="mut">Sin datos</td></tr>'}</table></div></div>
  <div class="card"><h2>Dominios</h2><div class="tbl"><table><tr><th>Dominio</th><th>Rol</th><th>Exp.</th><th>Partidos</th><th>Último</th></tr>${rows(k.dom, e => `<td>${esc(e.role || '')}</td>`) || '<tr><td colspan=5 class="mut">Sin datos</td></tr>'}</table></div></div>
  <div class="card"><h2>IPs</h2><div class="tbl"><table><tr><th>IP</th><th>ASN</th><th>Exp.</th><th>Partidos</th><th>Último</th></tr>${rows(k.ip, e => `<td>AS${esc(e.asn)}</td>`) || '<tr><td colspan=5 class="mut">Sin datos</td></tr>'}</table></div></div>`;
}

/* --- Licenciatarios y registro de marcas --- */
async function vLicencias() {
  const ms = allMatches();
  const mk = DB.marks.slice(-30).reverse();
  return `${hero('Licenciatarios', 'autorizados y el registro de marcas de agua emitidas.')}
  <div class="card"><h2>Licenciatarios autorizados</h2><p class="small mut">Dominios propios donde cada licenciatario puede exhibir la señal. Datos de ejemplo: revisalos y completalos con los contratos vigentes.</p>
  ${DB.licensees.map((l, i) => `<div class="card" style="background:var(--card2)"><div class="row sp"><b>${esc(l.name)}</b><span class="pill info">${esc(l.code)}</span></div><label>Dominios autorizados (separados por coma)</label><input value="${esc(l.domains.join(', '))}" onchange="setLicDomains(${i},this.value)"></div>`).join('')}
  <div class="grid"><div><label>Nombre</label><input id="lName"></div><div><label>Código (3 letras)</label><input id="lCode" maxlength="3"></div><div><label>Dominios</label><input id="lDom"></div></div><div class="row" style="margin-top:8px"><button onclick="addLic()">Agregar licenciatario</button></div></div>
  <div class="card"><h2>Registro de emisión de marcas</h2><p class="small mut">El sistema de marcado forense (en la cabecera del licenciatario) asigna un payload único por partido, licenciatario y sesión. Importá su export (un payload por línea, opcionalmente “payload,nota”) o generá marcas para pruebas.</p>
  <label>Importar payloads</label><textarea id="mkIn" class="mono" placeholder="AR-1A2B3C-ESP-0F3E9A11-7C2D,decodificador #4471"></textarea><div class="row" style="margin-top:8px"><button onclick="importMarks()">Importar</button></div>
  <h3>Generar marcas de prueba</h3><div class="grid"><div><label>Partido</label><select id="gM">${ms.map(m => `<option value="${esc(m.id)}">${esc(matchName(m))} · ${fmtD(m.kickoff)}</option>`).join('')}</select></div><div><label>Licenciatario</label><select id="gL">${DB.licensees.map(l => `<option value="${esc(l.code)}">${esc(l.name)}</option>`).join('')}</select></div><div><label>Cantidad</label><input id="gN" type="number" value="3" min="1" max="50"></div></div>
  <div class="row" style="margin-top:8px"><button class="ghost" onclick="genMarks()">Generar</button></div>
  <h3>Últimas marcas (${DB.marks.length})</h3><div class="tbl"><table><tr><th>Payload</th><th>Sesión / nota</th></tr>${mk.map(k => `<tr><td class="mono">${esc(k.payload)}</td><td>${esc(k.session)}${k.note ? ' · ' + esc(k.note) : ''}</td></tr>`).join('') || '<tr><td colspan=2 class="mut">Vacío</td></tr>'}</table></div></div>`;
}
window.setLicDomains = async (i, v) => { DB.licensees[i].domains = v.split(',').map(s => s.trim().toLowerCase()).filter(Boolean); save(); await audit('licenciatario_editado', null, DB.licensees[i].code + ': ' + v); toast('Guardado'); };
window.addLic = async () => { const code = $('#lCode').value.trim().toUpperCase(); if (!/^[A-Z]{3}$/.test(code)) return toast('Código de 3 letras'); DB.licensees.push({ id: uid(), code, name: $('#lName').value.trim() || code, domains: $('#lDom').value.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) }); save(); await audit('licenciatario_agregado', null, code); route(); };
window.importMarks = async () => {
  let n = 0;
  for (const line of $('#mkIn').value.split('\n')) {
    const [p, ...rest] = line.split(','); const payload = (p || '').trim().toUpperCase(); if (!/^AR-[0-9A-F]{6}-[A-Z]{3}-[0-9A-F]{8}-[0-9A-F]{4}$/.test(payload)) continue;
    if (DB.marks.some(k => k.payload === payload)) continue;
    DB.marks.push({ payload, session: payload.split('-')[3], note: rest.join(',').trim(), importedAt: new Date().toISOString() }); n++;
  }
  save(); await audit('marcas_importadas', null, `${n} payloads`); toast(`${n} marcas importadas`); route();
};
window.genMarks = async () => {
  const mid = $('#gM').value, lic = $('#gL').value, n = Math.min(50, +$('#gN').value || 1);
  for (let i = 0; i < n; i++) { const s = [...crypto.getRandomValues(new Uint8Array(4))].map(b => b.toString(16).padStart(2, '0')).join(''); DB.marks.push({ payload: await makePayload(mid, lic, s), session: s.toUpperCase(), note: 'prueba', matchId: mid }); }
  save(); await audit('marcas_generadas', null, `${n} ${lic} ${mid}`); route();
};

/* --- Banco de pruebas de marcas (servidor de prueba: /api/mock-payloads + /api/verify-mark) --- */
const HTTP_TXT = { 200: '200 OK', 400: '400 Bad Request', 403: '403 Forbidden', 422: '422 Unprocessable Entity' };
const httpPill = (s) => `<span class="pill ${s === 200 ? 'ok' : s === 403 ? 'bad' : 'warn'}">${esc(HTTP_TXT[s] || String(s))}</span>`;
let MOCK = null;
async function vPruebas() {
  return `${hero('Banco de pruebas', 'de marcas de agua contra un servidor de prueba.')}
  <div class="card"><h2>Servidor de pruebas</h2><p class="small mut">Valida payloads contra una base de prueba ficticia, sin señales reales de ningún licenciatario. Responde <b>200</b> si el payload es válido y figura como emitido, <b>403</b> si la señal no está autorizada (licenciatario, partido o sesión fuera de la base), <b>422</b> si el dígito de control no coincide y <b>400</b> si el formato es inválido.</p>
  <div class="row"><input id="tbIn" class="mono" placeholder="AR-XXXXXX-LIC-XXXXXXXX-XXXX" style="flex:1"><select id="tbM"><option value="">cualquier partido</option>${(MOCK ? MOCK.base.matches : []).map(m => `<option value="${esc(m.id)}">${esc(m.name)}</option>`).join('')}</select><button onclick="tbVerify()">Verificar</button></div><div id="tbOut"></div></div>
  <div class="card"><h2>Payloads simulados</h2><p class="small mut">El emisor mock genera payloads con la estructura del detector forense (payload, partido y metadatos del detector) y el código que el servidor debería devolver.</p>
  <div class="row"><button class="ghost" onclick="tbMock()">Generar payloads simulados</button>${MOCK ? '<button onclick="tbRunAll()">Verificar todos</button>' : ''}</div><div id="tbSum"></div>
  ${MOCK ? `<div class="tbl"><table><tr><th>Tipo</th><th>Payload</th><th>Esperado</th><th>Obtenido</th><th></th></tr>${MOCK.payloads.map((p, i) => `<tr><td>${esc(p.kind)}</td><td class="mono small">${esc(p.payload)}<div class="mut">${esc(p.matchId)} · confianza ${p.detector.confidence}</div></td><td>${httpPill(p.expected)}</td><td id="tbG${i}">${p.got ? httpPill(p.got) : '—'}</td><td id="tbR${i}">${p.got ? (p.got === p.expected ? '<i class="ck y"></i>' : '<i class="ck n"></i>') : ''}</td></tr>`).join('')}</table></div>` : ''}</div>
  ${MOCK ? `<div class="card"><h2>Base de prueba: marcas emitidas</h2><div class="tbl"><table><tr><th>Payload</th><th>Partido</th><th>Sesión</th></tr>${MOCK.base.marks.map(k => `<tr><td class="mono small">${esc(k.payload)}</td><td>${esc(k.matchId)}</td><td>${esc(k.session)} · ${esc(k.note)}</td></tr>`).join('')}</table></div></div>` : ''}`;
}
async function verifyMarkApi(payload, matchId) {
  const r = await fetch('/api/verify-mark', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ payload, matchId: matchId || undefined }) });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
window.tbVerify = async () => {
  const out = $('#tbOut'); out.innerHTML = '<p><span class="spin"></span> Consultando el servidor de pruebas…</p>';
  try {
    const { status, j } = await verifyMarkApi($('#tbIn').value, $('#tbM').value);
    out.innerHTML = `<p>${httpPill(status)} <span class="small mut">${esc(j.code || j.error || '')}</span></p><ul class="check small">${(j.checks || []).map(x => `<li><i class="ck ${x.ok ? 'y' : 'n'}"></i> ${esc(x.t)}</li>`).join('')}</ul>`;
  } catch { out.innerHTML = '<div class="verdict bad">Sin conexión con el servidor de pruebas</div>'; }
};
window.tbMock = async () => {
  try { const r = await fetch('/api/mock-payloads?n=14'); if (!r.ok) throw 0; MOCK = await r.json(); route(); } catch { toast('No respondió /api/mock-payloads'); }
};
window.tbRunAll = async () => {
  let ok = 0;
  for (const [i, p] of MOCK.payloads.entries()) {
    try { p.got = (await verifyMarkApi(p.payload, p.matchId)).status; } catch { p.got = 0; }
    if (p.got === p.expected) ok++;
    $('#tbG' + i).innerHTML = httpPill(p.got); $('#tbR' + i).innerHTML = `<i class="ck ${p.got === p.expected ? 'y' : 'n'}"></i>`;
  }
  $('#tbSum').innerHTML = `<div class="verdict ${ok === MOCK.payloads.length ? 'ok' : 'bad'}">${ok}/${MOCK.payloads.length} respuestas con el código esperado</div>`;
};

/* --- Verificar --- */
async function vVerificar() {
  return `${hero('Verificar', 'que ninguna captura ni expediente fue alterado.')}
  <div class="card"><h2>¿Este archivo es la captura original?</h2><p class="small mut">Elegí un archivo: se calcula su SHA-256 y se busca en todos los expedientes.</p><input type="file" onchange="verifyFile(this.files[0])"><div id="vf"></div></div>
  <div class="card"><h2>¿El expediente fue alterado?</h2><p class="small mut">Cargá el JSON exportado de un expediente sellado: se recalcula el hash y se compara con el sellado ante la TSA.</p><input type="file" accept=".json" onchange="verifyJson(this.files[0])"><div id="vj"></div></div>
  <div class="card"><h2>Expedientes en este dispositivo</h2><button class="ghost" onclick="verifyLocal()">Verificar todos</button><div id="vl"></div></div>`;
}
window.verifyFile = async (f) => {
  if (!f) return; $('#vf').innerHTML = '<p><span class="spin"></span> Calculando…</p>';
  const h = await sha256File(f);
  const hits = []; for (const c of DB.cases) { c.captures.forEach(x => x.sha256 === h && hits.push([c, x])); c.promos.forEach(x => x.sha256 === h && hits.push([c, x])); }
  $('#vf').innerHTML = `<div class="mono">${h}</div>` + (hits.length ? hits.map(([c, x]) => `<div class="verdict ok">✔ Coincide con ${esc(c.num)} · ${esc(x.name || x.file)} · sellado ${fmt(x.tsa && x.tsa.genTime)}</div>`).join('') : '<div class="verdict bad">✖ No coincide con ninguna captura registrada (o el archivo fue modificado).</div>');
};
async function checkCase(c) {
  if (!c.seal) return { ok: null, t: 'Borrador (sin sellar)' };
  const h = await sha256Hex(stable(sealPayload(c)));
  return h === c.seal.sha256 ? { ok: true, t: `Íntegro · sellado ${fmt(c.seal.tsa && c.seal.tsa.genTime)}` } : { ok: false, t: `ALTERADO: hash actual ${h.slice(0, 16)}… ≠ sellado ${c.seal.sha256.slice(0, 16)}…` };
}
window.verifyJson = async (f) => {
  if (!f) return; try {
    const j = JSON.parse(await f.text()); const c = j.case; const r = await checkCase(c);
    const au = j.audit && j.audit.length ? '' : '';
    $('#vj').innerHTML = `<div class="verdict ${r.ok ? 'ok' : r.ok === false ? 'bad' : 'warn'}">${esc(c.num)}: ${esc(r.t)}</div>${c.seal && c.seal.tsa ? `<p class="small">Sello TSA: ${esc(c.seal.tsa.genTime)} · imprint ${c.seal.tsa.imprintPresent ? 'presente' : '—'}${c.seal.tsa.demo ? ' · <b>SIMULADO (DEMO), sin valor probatorio</b>' : ''}</p>` : ''}${au}`;
  } catch { $('#vj').innerHTML = '<div class="verdict bad">JSON inválido</div>'; }
};
window.verifyLocal = async () => { let h = ''; for (const c of DB.cases) { const r = await checkCase(c); h += `<div class="verdict ${r.ok ? 'ok' : r.ok === false ? 'bad' : 'warn'} small">${esc(c.num)}: ${esc(r.t)}</div>`; } $('#vl').innerHTML = h || '<p class="mut">Sin expedientes</p>'; };

/* --- Auditoría --- */
async function vAuditoria() {
  const v = await verifyAudit();
  return `${hero('Auditoría', 'de cada acción, encadenada por hash.')}<div class="verdict ${v.ok ? 'ok' : 'bad'}">${v.ok ? `✔ Registro íntegro: ${v.n} eventos encadenados por hash` : `✖ Registro alterado en el evento #${v.at}: ${esc(v.why)}`}</div>
  <div class="row"><button class="ghost" onclick="download('auditoria.json', JSON.stringify(DB.audit,null,1))">Exportar registro</button></div>
  <div class="card tbl" style="margin-top:10px"><table><tr><th>#</th><th>Fecha</th><th>Acción</th><th>Detalle</th><th>Hash</th></tr>${DB.audit.slice().reverse().map(e => `<tr><td>${e.i}</td><td>${fmt(e.ts)}</td><td>${esc(e.action)}${e.caseId && getCase(e.caseId) ? `<div><a href="#/exp/${e.caseId}">${esc(getCase(e.caseId).num)}</a></div>` : ''}</td><td class="small">${esc(e.detail)}</td><td class="mono small">${e.hash.slice(0, 12)}…</td></tr>`).join('')}</table></div>`;
}

/* --- Demo --- */
/* ===== Inicio ===== */
$('#menuBtn').onclick = () => document.body.classList.toggle('menu');
$('#nav').addEventListener('click', (e) => { if (e.target.closest('a')) document.body.classList.remove('menu'); });
window.addEventListener('DOMContentLoaded', () => { loadFixtures().then(route); route(); });
