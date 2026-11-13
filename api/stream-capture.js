const L = require('./_lib');
const H = require('./_hls');

// Captura del stream: baja el manifiesto, comprueba que esté en vivo y hashea los últimos segmentos.
const SEG_MAX = 6000000;
const SAMPLE_MAX = 2500000;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function getText(url, ref) {
  const { res, finalUrl } = await H.fetchSafe(url, ref);
  const { buf } = await H.readCapped(res, 400000);
  return { status: res.status, finalUrl, text: buf.toString('utf8'), sha256: L.sha256(buf), at: new Date().toISOString() };
}

async function freshManifest(url, page, pref) {
  const { res } = await H.fetchSafe(page, pref, 8000, 'iframe');
  const { buf } = await H.readCapped(res, 1500000);
  const want = new URL(url); const key = want.pathname;
  const found = (buf.toString('utf8').replace(/\\\//g, '/').match(/https?:\/\/[^"'\s<>()]+?\.m3u8[^"'\s<>()]*/gi) || []).map(u => { try { return new URL(u); } catch { return null; } }).filter(Boolean);
  const same = found.find(u => u.pathname === key && u.hostname.split('.').slice(-2).join('.') === want.hostname.split('.').slice(-2).join('.'));
  return same ? same.href : url;
}

module.exports = async (req, res) => {
  const q = req.query || {};
  let url = String(q.url || '').trim(); const ref = String(q.ref || '').trim() || null;
  const page = String(q.page || '').trim() || null; const pref = String(q.pref || '').trim() || null;
  try { url = new URL(url).href; if (ref) new URL(ref); if (page) new URL(page); if (pref) new URL(pref); } catch { return L.send(res, 400, { error: 'URL del manifiesto inválida' }); }
  const startedAt = new Date().toISOString();
  let tokenRefreshed = false;
  try {
    // Muchos streams piratas firman el .m3u8 con un token atado a la IP que abrió el reproductor:
    // se vuelve a abrir la página del reproductor desde acá para usar un token propio.
    if (page) url = await freshManifest(url, page, pref).then(u => { tokenRefreshed = u !== url; return u; }).catch(() => url);
    let m = await getText(url, ref);
    if (!m.text.includes('#EXTM3U')) return L.send(res, 422, { error: 'No es un manifiesto HLS (.m3u8)', status: m.status });
    let variant = null;
    const vs = H.parseMaster(m.text, m.finalUrl);
    if (vs.length) {
      variant = H.pickVariant(vs);
      m = await getText(variant.url, ref);
      if (!m.text.includes('#EXTM3U')) return L.send(res, 422, { error: 'La variante no es un manifiesto HLS', status: m.status });
    }
    const mediaUrl = variant ? variant.url : url;
    const p1 = H.parseMedia(m.text, m.finalUrl);
    if (!p1.segments.length) return L.send(res, 422, { error: 'El manifiesto no lista segmentos' });

    const live = { endList: p1.endList, playlistType: p1.playlistType, firstSequence: p1.mediaSequence, firstAt: m.at, secondSequence: null, secondAt: null, advanced: null };
    let p = p1, mediaSha = m.sha256;
    if (!p1.endList && p1.playlistType !== 'VOD') {
      await sleep(Math.min(Math.max((p1.targetDuration || 4) * 1000 + 500, 2500), 7000));
      const m2 = await getText(mediaUrl, ref);
      const p2 = H.parseMedia(m2.text, m2.finalUrl);
      Object.assign(live, { secondSequence: p2.mediaSequence, secondAt: m2.at, advanced: p2.mediaSequence > p1.mediaSequence || (p2.segments.length > 0 && p2.segments[p2.segments.length - 1].url !== p1.segments[p1.segments.length - 1].url) });
      if (p2.segments.length) { p = p2; mediaSha = m2.sha256; }
    }
    live.isLive = !live.endList && live.advanced === true;

    const pick = live.endList || p.playlistType === 'VOD' ? p.segments.slice(0, 2) : p.segments.slice(-3, -1).length ? p.segments.slice(-3, -1) : p.segments.slice(-1);
    let sample = null;
    const segments = [];
    for (const s of pick) {
      const t0 = new Date().toISOString();
      try {
        const { res: r, finalUrl } = await H.fetchSafe(s.url, ref, 10000);
        const { buf, truncated } = await H.readCapped(r, SEG_MAX);
        const seg = { url: s.url, finalUrl, seq: s.seq, duration: s.duration, programDateTime: s.programDateTime, status: r.status, contentType: r.headers.get('content-type'), server: r.headers.get('server'), bytes: buf.length, truncated, sha256: L.sha256(buf), fetchedAt: t0 };
        segments.push(seg);
        if (!sample && r.status < 400 && !truncated && buf.length <= SAMPLE_MAX) sample = { seq: s.seq, sha256: seg.sha256, b64: buf.toString('base64') };
      } catch (e) { segments.push({ url: s.url, seq: s.seq, error: e.message, fetchedAt: t0 }); }
    }
    return L.send(res, 200, {
      manifest: url, referer: ref, page, tokenRefreshed, variant, mediaPlaylist: mediaUrl, mediaPlaylistSha256: mediaSha, startedAt, finishedAt: new Date().toISOString(),
      targetDuration: p.targetDuration, encrypted: p.key, fmp4: !!p.map, programDateTime: p.programDateTime, live, segments, sample,
      capturer: 'expedientes-futbol/stream (Vercel)',
    });
  } catch (e) {
    return L.send(res, e.code || 502, { error: e.code ? e.message : (e.name === 'AbortError' ? 'El servidor de video no respondió a tiempo' : 'El servidor de video no responde') });
  }
};
