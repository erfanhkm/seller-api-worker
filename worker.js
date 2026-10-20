// seller-api worker — seller portal backend for virtual tours.
// KV binding: PORTAL (same namespace as the advisor worker's LEADS binding;
//   keys: seller:<email>, stok:<token>, tour:<listingId>, tok:<advisor-token>,
//         pano:<listingId>/<id>.jpg  (panorama binaries, stored in KV —
//         R2 was dropped because activation requires a payment method)
//
// Endpoints:
//   GET  /api/health                              (public)
//   POST /api/seller/invite  {email,listingId}    (advisor auth)
//   POST /api/seller/login   {email,password}     (public, rate-limited)
//   GET  /api/seller/me                           (seller auth)
//   POST /api/seller/panorama  (multipart, file)  (seller auth)
//   DELETE /api/seller/panorama/:id               (seller auth)
//   GET  /api/seller/tour                         (seller auth)
//   PUT  /api/seller/tour {rooms,hotspots,enabled,videoUrl} (seller auth)
//   GET  /api/tour/:listingId                     (public — main site viewer)

const ALLOWED_ORIGINS = [
  'https://real-estate-platform-0aei.onrender.com',
  'https://muse.ai',
  'null'
];
const MAX_PANO_BYTES = 15 * 1024 * 1024;

function cors(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json' }, cors(origin))
  });
}

const hits = new Map();
function limited(ip, max, windowMs) {
  const now = Date.now();
  const k = ip + ':' + max + ':' + windowMs;
  let r = hits.get(k);
  if (!r || now > r.reset) { r = { count: 0, reset: now + 3600000 }; hits.set(k, r); }
  r.count++;
  return r.count > max;
}

async function sha256hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function randHex(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}
function bearerToken(request) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer ([0-9a-f]{64})$/);
  return m ? m[1] : null;
}
// Advisor tokens live as tok:<token> in the shared KV (created by advisor-api).
async function advisorAuthed(request, env) {
  const t = bearerToken(request);
  if (!t) return false;
  const exp = await env.PORTAL.get('tok:' + t);
  if (!exp) return false;
  if (Date.now() > parseInt(exp, 10)) {
    await env.PORTAL.delete('tok:' + t).catch(() => {});
    return false;
  }
  return true;
}
async function sellerAuthed(request, env) {
  const t = bearerToken(request);
  if (!t) return null;
  const raw = await env.PORTAL.get('stok:' + t);
  if (!raw) return null;
  let s = null;
  try { s = JSON.parse(raw); } catch (e) {}
  if (!s || Date.now() > s.exp) {
    await env.PORTAL.delete('stok:' + t).catch(() => {});
    return null;
  }
  return s; // {email, listingId}
}
function emailOk(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }

function defaultTour() {
  return { enabled: false, rooms: [], hotspots: [], videoUrl: '' };
}
function sanitizeTour(t) {
  t = t || {};
  const rooms = Array.isArray(t.rooms) ? t.rooms.slice(0, 30).map(r => ({
    id: String(r.id || '').slice(0, 40),
    name: String(r.name || '').slice(0, 80),
    url: String(r.url || '').slice(0, 500)
  })).filter(r => r.id && r.url) : [];
  const roomIds = {};
  rooms.forEach(r => { roomIds[r.id] = true; });
  const hotspots = Array.isArray(t.hotspots) ? t.hotspots.slice(0, 120).map(h => ({
    from: String(h.from || '').slice(0, 40),
    to: String(h.to || '').slice(0, 40),
    yaw: Math.max(-180, Math.min(180, parseFloat(h.yaw) || 0)),
    pitch: Math.max(-90, Math.min(90, parseFloat(h.pitch) || 0)),
    text: String(h.text || '').slice(0, 80)
  })).filter(h => roomIds[h.from] && roomIds[h.to] && h.from !== h.to) : [];
  return {
    enabled: t.enabled === true,
    rooms: rooms,
    hotspots: hotspots,
    videoUrl: String(t.videoUrl || '').slice(0, 500)
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors(origin) });
    if (origin && !ALLOWED_ORIGINS.includes(origin)) {
      return new Response(JSON.stringify({ ok: false, error: 'forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    try {
      if (path === '/api/health') return json({ ok: true }, 200, origin);

      // ---- advisor: invite a seller (creates seller account) ----
      if (path === '/api/seller/invite' && request.method === 'POST') {
        if (!(await advisorAuthed(request, env))) return json({ ok: false, error: 'unauthorized' }, 401, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const email = String(d.email || '').trim().toLowerCase();
        const listingId = String(d.listingId || '').trim().slice(0, 40);
        if (!emailOk(email) || !listingId) return json({ ok: false, error: 'validation' }, 400, origin);
        if (await env.PORTAL.get('seller:' + email)) return json({ ok: false, error: 'exists' }, 400, origin);
        const password = (typeof d.password === 'string' && d.password.length >= 4 && d.password.length <= 100) ? d.password : 'sel-' + randHex(12);
        const salt = randHex(16);
        const hash = await sha256hex(salt + ':' + password);
        await env.PORTAL.put('seller:' + email, JSON.stringify({ email: email, salt: salt, hash: hash, listingId: listingId, created_at: new Date().toISOString() }));
        // NOTE: password is returned ONCE here; the advisor hands it to the seller.
        return json({ ok: true, email: email, password: password, listingId: listingId }, 200, origin);
      }

      // ---- seller: login ----
      if (path === '/api/seller/login' && request.method === 'POST') {
        if (limited(ip, 10, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const email = String((d && d.email) || '').trim().toLowerCase();
        const pw = d && typeof d.password === 'string' ? d.password : '';
        const raw = await env.PORTAL.get('seller:' + email);
        let s = null;
        try { s = raw ? JSON.parse(raw) : null; } catch (e) {}
        const good = s && pw && timingSafeEqual(await sha256hex(s.salt + ':' + pw), s.hash);
        if (!good) return json({ ok: false, error: 'invalid' }, 401, origin);
        const token = randHex(32);
        const exp = Date.now() + 7 * 86400 * 1000; // 7 days
        await env.PORTAL.put('stok:' + token, JSON.stringify({ email: email, listingId: s.listingId, exp: exp }), { expirationTtl: 7 * 86400 });
        return json({ ok: true, token: token, listingId: s.listingId }, 200, origin);
      }

      // ---- seller authed routes ----
      const seller = await sellerAuthed(request, env);
      const needSeller = path.startsWith('/api/seller/') && path !== '/api/seller/login' && path !== '/api/seller/invite';
      if (needSeller && !seller) return json({ ok: false, error: 'unauthorized' }, 401, origin);

      if (path === '/api/seller/me' && request.method === 'GET') {
        return json({ ok: true, email: seller.email, listingId: seller.listingId }, 200, origin);
      }

      if (path === '/api/seller/panorama' && request.method === 'POST') {
        if (limited(ip, 30, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const form = await request.formData().catch(() => null);
        const file = form && form.get('file');
        if (!file || typeof file.arrayBuffer !== 'function') return json({ ok: false, error: 'validation' }, 400, origin);
        const ctype = file.type || '';
        if (!ctype.startsWith('image/')) return json({ ok: false, error: 'not_image' }, 400, origin);
        const buf = await file.arrayBuffer();
        if (buf.byteLength > MAX_PANO_BYTES || buf.byteLength < 1024) return json({ ok: false, error: 'bad_size' }, 400, origin);
        const id = Date.now().toString(36) + '-' + randHex(6);
        const key = seller.listingId + '/' + id + '.jpg';
        await env.PORTAL.put('pano:' + key, buf);
        const base = new URL(request.url).origin;
        return json({ ok: true, id: id, url: base + '/api/pano/' + key }, 200, origin);
      }

      let m = path.match(/^\/api\/seller\/panorama\/([A-Za-z0-9-]+)$/);
      if (m && request.method === 'DELETE') {
        const key = seller.listingId + '/' + m[1] + '.jpg';
        await env.PORTAL.delete('pano:' + key).catch(() => {});
        // also drop the room referencing it
        const tkey = 'tour:' + seller.listingId;
        const tour = sanitizeTour(await env.PORTAL.get(tkey, { type: 'json' }));
        tour.rooms = tour.rooms.filter(r => r.id !== m[1]);
        tour.hotspots = tour.hotspots.filter(h => h.from !== m[1] && h.to !== m[1]);
        await env.PORTAL.put(tkey, JSON.stringify(tour));
        return json({ ok: true }, 200, origin);
      }

      if (path === '/api/seller/tour' && request.method === 'GET') {
        const tour = sanitizeTour(await env.PORTAL.get('tour:' + seller.listingId, { type: 'json' }));
        return json({ ok: true, tour: tour }, 200, origin);
      }
      if (path === '/api/seller/tour' && request.method === 'PUT') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const tour = sanitizeTour(d);
        if (tour.enabled && tour.rooms.length === 0) return json({ ok: false, error: 'no_rooms' }, 400, origin);
        await env.PORTAL.put('tour:' + seller.listingId, JSON.stringify(tour));
        return json({ ok: true, tour: tour }, 200, origin);
      }

      // ---- public: tour for the main-site viewer ----
      m = path.match(/^\/api\/tour\/([A-Za-z0-9-]+)$/);
      if (m && request.method === 'GET') {
        const tour = sanitizeTour(await env.PORTAL.get('tour:' + m[1], { type: 'json' }));
        if (!tour.enabled || tour.rooms.length === 0) return json({ ok: false, error: 'no_tour' }, 404, origin);
        return json({ ok: true, tour: tour }, 200, origin);
      }

      // ---- public: panorama image served from KV ----
      m = path.match(/^\/api\/pano\/([A-Za-z0-9-]+\/[A-Za-z0-9-]+\.jpg)$/);
      if (m && request.method === 'GET') {
        const img = await env.PORTAL.get('pano:' + m[1], { type: 'arrayBuffer' });
        if (!img) return json({ ok: false, error: 'not_found' }, 404, origin);
        return new Response(img, {
          headers: {
            'Content-Type': 'image/jpeg',
            'Cache-Control': 'public, max-age=86400',
            'Access-Control-Allow-Origin': origin || '*'
          }
        });
      }

      return json({ ok: false, error: 'not_found' }, 404, origin);
    } catch (e) {
      return json({ ok: false, error: 'server' }, 500, origin);
    }
  }
};
