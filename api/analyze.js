const L = require('./_lib');
const F = require('./_futbol');
const { browserHeaders } = require('./_hls');

const VIDEO_RE = /https?:\\?\/\\?\/[^"'\s<>()]+?\.(?:m3u8|mpd|mp4|flv|ts)(?:\?[^"'\s<>()]*)?/gi;
const IFRAME_RE = /<(?:iframe|embed)[^>]+?(?:src|data-src)\s*=\s*["']([^"']+)["']/gi;
const SOURCE_RE = /<(?:source|video)[^>]+?src\s*=\s*["']([^"']+)["']/gi;
const JSKEY_RE = /(?:file|source|src|hls|url|stream)\s*[:=]\s*["'](https?:\/\/[^"']+|\/\/[^"']+)["']/gi;
const ATOB_RE = /atob\(\s*["']([A-Za-z0-9+/=]{16,})["']\s*\)/g;

function abs(u, base) {
  try { u = u.replace(/\\\//g, '/'); if (u.startsWith('//')) u = 'https:' + u; return new URL(u, base).href; } catch { return null; }
}
function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch { return null; } }

function pickHeaders(h) {
  const keys = ['server', 'via', 'x-cache', 'cf-ray', 'x-amz-cf-id', 'x-amz-cf-pop', 'x-served-by', 'x-akamai-request-id', 'x-cdn', 'content-type', 'date', 'x-powered-by'];
  const o = {}; for (const k of keys) { const v = h.get(k); if (v) o[k] = v.slice(0, 160); } return o;
}
function cdnFromHeaders(h) {
  if (!h) return null;
  const s = (h.server || '').toLowerCase();
  if (h['cf-ray'] || s.includes('cloudflare')) return 'Cloudflare';
  if (h['x-amz-cf-id'] || /cloudfront/i.test(h.via || '')) return 'Amazon CloudFront';
  if (/fastly/i.test(h['x-served-by'] || '') || /varnish/i.test(h.via || '')) return 'Fastly/Varnish';
  if (h['x-akamai-request-id'] || s.includes('akamai')) return 'Akamai';
  if (s.includes('bunnycdn')) return 'BunnyCDN';
  if (h['x-cdn']) return h['x-cdn'];
  return null;
}

async function safeHost(host) {
  const r = await L.resolve(host);
  const ips = [...r.a, ...r.aaaa];
  if (!ips.length) return { ok: false, r };
  if (ips.some(L.isPrivateIP)) return { ok: false, r, private: true };
  return { ok: true, r };
}

async function grab(url, referer, maxBytes = 1500000, mode = 'xhr') {
  const host = hostOf(url);
  if (!host) return { url, error: 'URL inválida' };
  const sh = await safeHost(host);
  if (!sh.ok) return { url, error: sh.private ? 'host privado bloqueado' : 'no resuelve DNS' };
  const t0 = new Date().toISOString();
  try {
    const r = await L.fetchT(url, { redirect: 'follow', headers: browserHeaders(referer, mode) }, 8000);
    const buf = Buffer.from(await r.arrayBuffer()).subarray(0, maxBytes);
    return { url, finalUrl: r.url, status: r.status, fetchedAt: t0, headers: pickHeaders(r.headers), sha256: L.sha256(buf), bytes: buf.length, text: buf.toString('utf8') };
  } catch (e) { return { url, fetchedAt: t0, error: e.name === 'AbortError' ? 'timeout' : 'no responde' }; }
}

const LINK_RE = /<a\s[^>]*?href\s*=\s*["']([^"'#][^"']*)["'][^>]*>([\s\S]{0,300}?)<\/a>/gi;
const PLAYER_LINK = /canal|channel|evento|partido|vivo|live|ver-|stream|player|embed|reproductor|tv\b/i;
const strip = (s) => s.replace(/<[^>]+>/g, ' ').replace(/&nbsp;|&#160;/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
// URL escondida en base64 dentro de un parámetro (p. ej. eventos.html?r=aHR0cHM6Ly9...)
function b64Url(u) {
  try { for (const v of new URL(u).searchParams.values()) { if (!/^[A-Za-z0-9+/=_-]{16,}$/.test(v)) continue; const d = Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'); if (/^https?:\/\/[^\s"'<>]+$/.test(d)) return d; } } catch {}
  return null;
}
// Enlaces de una portada o agenda que llevan a un reproductor (canal o partido), con el partido que los encabeza.
function playerLinks(html, base) {
  const out = []; const seen = new Set(); let m; const bh = hostOf(base);
  LINK_RE.lastIndex = 0;
  while ((m = LINK_RE.exec(html)) && out.length < 40) {
    const url = abs(m[1], base); if (!url || !/^https?:/.test(url) || seen.has(url)) continue;
    if (/\.(css|js|png|jpe?g|webp|svg|ico|gif)(\?|$)|dmca|privacidad|contacto|login|register/i.test(url)) continue;
    const label = strip(m[2]).slice(0, 80); const hidden = b64Url(url);
    if (hostOf(url) !== bh && !hidden) continue;
    if (!PLAYER_LINK.test(url) && !hidden) continue;
    const evs = [...html.slice(Math.max(0, m.index - 2500), m.index).matchAll(/>([^<>]{4,160}?\b(?:vs\.?|v)\s[^<>]{2,120})</gi)];
    const ctx = evs.length ? strip(evs[evs.length - 1][1]).replace(/&#0?39;/g, "'").replace(/\s*\d{1,2}:\d{2}.*$/, '') : null;
    seen.add(url); out.push({ url, label, event: ctx && ctx.slice(-90), hidden });
  }
  return out;
}

function extract(html, base) {
  const iframes = new Set(), videos = new Set();
  let m;
  const scan = (txt) => {
    for (const re of [IFRAME_RE]) { re.lastIndex = 0; while ((m = re.exec(txt))) { const u = abs(m[1], base); if (u && /^https?:/.test(u)) iframes.add(u); } }
    SOURCE_RE.lastIndex = 0; while ((m = SOURCE_RE.exec(txt))) { const u = abs(m[1], base); if (u) videos.add(u); }
    VIDEO_RE.lastIndex = 0; while ((m = VIDEO_RE.exec(txt))) { const u = abs(m[0], base); if (u) videos.add(u); }
    JSKEY_RE.lastIndex = 0; while ((m = JSKEY_RE.exec(txt))) { const u = abs(m[1], base); if (u && /\.(m3u8|mpd|mp4|flv)/i.test(u)) videos.add(u); else if (u && !/\.(js|css)(\?|$)/i.test(u) && /embed|player|stream|live|canal|channel/i.test(u)) iframes.add(u); }
  };
  scan(html);
  ATOB_RE.lastIndex = 0;
  while ((m = ATOB_RE.exec(html))) { try { scan(Buffer.from(m[1], 'base64').toString('utf8')); } catch {} }
  const title = (html.match(/<title[^>]*>([^<]{0,160})/i) || [])[1] || null;
  const hidden = b64Url(base); if (hidden) iframes.add(hidden);
  return { iframes: [...iframes].slice(0, 6), videos: [...videos].slice(0, 8), title: title && title.trim(), links: playerLinks(html, base) };
}

async function crawl(url, referer, depth, seen, nodes) {
  if (seen.has(url) || nodes.length >= 10) return;
  seen.add(url);
  const g = await grab(url, referer, 1500000, depth ? 'iframe' : 'document');
  const node = { url, referer: referer || null, depth, finalUrl: g.finalUrl, status: g.status, error: g.error, fetchedAt: g.fetchedAt, headers: g.headers, sha256: g.sha256, bytes: g.bytes, iframes: [], videos: [] };
  nodes.push(node);
  if (g.text) {
    const ex = extract(g.text, g.finalUrl || url);
    node.title = ex.title; node.iframes = ex.iframes; node.videos = ex.videos; node.signals = F.footballSignals(g.text); if (depth < 2) node.links = ex.links;
    if (depth < 2) await Promise.all(ex.iframes.slice(0, 3).map(f => crawl(f, g.finalUrl || url, depth + 1, seen, nodes)));
  }
}

async function probeVideo(url, referer) {
  const g = await grab(url, referer, 200000);
  const out = { url, referer, status: g.status, error: g.error, headers: g.headers, fetchedAt: g.fetchedAt, sha256: g.sha256, type: null, segments: [] };
  if (!g.text) return out;
  const head = g.text.slice(0, 20);
  if (head.includes('#EXTM3U')) {
    out.type = 'HLS (m3u8)';
    const lines = g.text.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#'));
    const base = g.finalUrl || url;
    const first = lines[0] && abs(lines[0], base);
    if (first && /\.m3u8/i.test(first)) {
      out.variant = first;
      const v = await grab(first, referer, 200000);
      if (v.text && v.text.includes('#EXTM3U')) {
        const segs = v.text.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#')).slice(0, 3);
        out.segments = segs.map(s => abs(s, v.finalUrl || first)).filter(Boolean);
      }
    } else if (first) out.segments = lines.slice(0, 3).map(s => abs(s, base)).filter(Boolean);
  } else if (/<MPD/i.test(g.text.slice(0, 500))) out.type = 'DASH (mpd)';
  else if (/video|octet-stream|mp2t/i.test((g.headers && g.headers['content-type']) || '')) out.type = 'Video directo';
  return out;
}

module.exports = async (req, res) => {
  try {
    const q = req.query || Object.fromEntries(new URL(req.url, 'http://x').searchParams);
    let target = (q.url || '').trim();
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
    const extraVideo = (q.video || '').trim();
    if (!hostOf(target)) return L.send(res, 400, { error: 'URL inválida' });
    const startedAt = new Date().toISOString();

    const nodes = [];
    await crawl(target, null, 0, new Set(), nodes);

    const videoRefs = [];
    for (const n of nodes) for (const v of n.videos) videoRefs.push([v, n.finalUrl || n.url, n.referer]);
    if (extraVideo) videoRefs.unshift([/^https?:/.test(extraVideo) ? extraVideo : 'https://' + extraVideo, target]);
    const uniq = []; const vs = new Set();
    for (const [v, r, pr] of videoRefs) if (!vs.has(v)) { vs.add(v); uniq.push([v, r, pr]); }
    const probes = await Promise.all(uniq.slice(0, 5).map(async ([v, r, pr]) => Object.assign(await probeVideo(v, r), { pageReferer: pr || null })));

    // hosts por rol
    const roles = new Map();
    const addRole = (u, role) => { const h = hostOf(u); if (!h) return; if (!roles.has(h)) roles.set(h, new Set()); roles.get(h).add(role); };
    addRole(target, 'pagina');
    nodes.forEach(n => { if (n.depth > 0) addRole(n.url, 'embed'); if (n.finalUrl && n.finalUrl !== n.url) addRole(n.finalUrl, n.depth ? 'embed' : 'pagina'); });
    probes.forEach(p => { addRole(p.url, 'manifiesto'); if (p.variant) addRole(p.variant, 'manifiesto'); p.segments.forEach(s => addRole(s, 'segmentos')); });

    const hostList = [...roles.keys()].slice(0, 10);
    const hosts = await Promise.all(hostList.map(async (h) => {
      const r = await L.resolve(h);
      const ips = r.a.slice(0, 3);
      const intel = await Promise.all(ips.map(L.ipIntel));
      let cdnCname = null;
      for (const c of r.cname) for (const [re, name] of L.CDN_CNAME) if (re.test(c)) cdnCname = name;
      const hdrNode = nodes.find(n => hostOf(n.finalUrl || n.url) === h) || probes.find(p => hostOf(p.url) === h);
      const cdnHeader = cdnFromHeaders(hdrNode && hdrNode.headers);
      return { host: h, roles: [...roles.get(h)], a: r.a, aaaa: r.aaaa.slice(0, 2), cname: r.cname, ips: intel, cdnCname, cdnHeader };
    }));

    // reverse IP (riesgo colateral) para hosts de entrega y página
    const delivery = hosts.filter(h => h.roles.some(r => r === 'segmentos' || r === 'manifiesto'));
    const priority = [...delivery, ...hosts.filter(h => h.roles.includes('pagina'))];
    const revTargets = [...new Set(priority.map(h => h.a[0]).filter(Boolean))].slice(0, 3);
    const rev = Object.fromEntries(await Promise.all(revTargets.map(async ip => [ip, await L.reverseIP(ip)])));

    for (const h of hosts) {
      const ip0 = h.ips[0];
      h.reverse = h.a[0] && rev[h.a[0]] ? rev[h.a[0]] : null;
      const sharedCount = h.reverse && h.reverse.count;
      const isCdn = !!(h.cdnCname || h.cdnHeader || (ip0 && (ip0.kind === 'cdn')));
      const isCloud = ip0 && ip0.kind === 'cloud';
      const shared = isCdn || isCloud || (sharedCount != null && sharedCount > 5);
      h.collateral = {
        isCdn, isCloud, sharedCount: sharedCount ?? null,
        level: isCdn || (sharedCount > 50) ? 'alto' : shared ? 'medio' : (sharedCount != null ? 'bajo' : 'sin datos'),
        recommendation: shared ? 'bloquear_dominio' : (sharedCount != null ? 'bloquear_ip_y_dominio' : 'bloquear_dominio'),
        reason: isCdn ? `La IP pertenece a una CDN (${h.cdnCname || h.cdnHeader || ip0.kindLabel}); bloquearla afectaría a miles de sitios legítimos.`
          : isCloud ? `IP de nube pública (${ip0.kindLabel}); suele ser compartida o reasignable.`
          : sharedCount > 5 ? `La IP aloja ${sharedCount} dominios (hosting compartido).`
          : sharedCount != null ? `La IP aloja ${sharedCount} dominio(s): servidor dedicado, bloqueo por IP con bajo riesgo colateral.`
          : 'No se pudo determinar cuántos sitios comparten la IP: por prudencia, bloquear por dominio.',
      };
    }

    const pageDomain = hostOf(target);
    const deliveryHost = (hosts.find(h => h.roles.includes('segmentos')) || hosts.find(h => h.roles.includes('manifiesto')) || null);
    const rdapTargets = [...new Set([pageDomain, deliveryHost && deliveryHost.host].filter(Boolean))];
    const rdap = await Promise.all(rdapTargets.map(L.rdapDomain));

    const signals = F.mergeSignals(nodes.map(n => n.signals)); nodes.forEach(n => delete n.signals);
    const seenL = new Set(); const playerPages = [];
    for (const n of nodes) { for (const l of n.links || []) if (!seenL.has(l.url) && l.url !== target) { seenL.add(l.url); playerPages.push(l); } delete n.links; }
    signals.playerPages = playerPages.slice(0, 30);
    const report = {
      target, startedAt, finishedAt: new Date().toISOString(), analyzer: 'expedientes-futbol/1.0 (Vercel)',
      chain: nodes, video: probes, hosts, rdap,
      deliveryHost: deliveryHost ? deliveryHost.host : null,
      signals,
      notes: deliveryHost ? [] : [playerPages.length ? 'Esta página parece una portada o agenda: no tiene reproductor propio. Elegí abajo el canal o partido para analizar su reproductor.' : 'No se detectó automáticamente el servidor de video (puede cargarse por JavaScript ofuscado o requerir sesión). Pegá la URL .m3u8 desde las herramientas de red del navegador en "URL del video".'],
    };
    report.reportSha256 = L.sha256(JSON.stringify(report));
    return L.send(res, 200, report);
  } catch (e) {
    return L.send(res, 500, { error: 'Fallo el análisis', detail: String(e && e.message || e).slice(0, 200) });
  }
};
