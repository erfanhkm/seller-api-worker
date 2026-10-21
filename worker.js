// site-admin tour API — virtual-tour backend, managed ONLY by the site admin
// (the realtor). There are no seller accounts: the admin uploads panoramas
// and configures tours for any listing from the admin portal.
// KV binding: PORTAL (same namespace as the advisor worker's LEADS binding;
//   keys: tour:<listingId>, tok:<advisor-token>,
//         pano:<listingId>/<id>.jpg  (panorama binaries, stored in KV —
//         R2 was dropped because activation requires a payment method)
//
// Endpoints:
//   GET    /api/health                                   (public)
//   GET    /api/admin/tours                              (admin auth — list all tours)
//   GET    /api/admin/tour?listingId=X                   (admin auth)
//   PUT    /api/admin/tour {listingId,rooms,hotspots,enabled,videoUrl} (admin auth)
//   POST   /api/admin/panorama  (multipart: file, listingId)           (admin auth)
//   DELETE /api/admin/panorama/:listingId/:id                          (admin auth)
//   GET    /api/tour/:listingId                          (public — main site viewer)
//   GET    /api/pano/:listingId/:id.jpg                  (public — panorama image)

const ALLOWED_ORIGINS = [
  'https://real-estate-platform-0aei.onrender.com',
  'https://muse.ai'
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
// Admin tokens live as tok:<token> in the shared KV (created by advisor-api login).
async function adminAuthed(request, env) {
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
function listingIdOk(id) { return /^[A-Za-z0-9-]{1,40}$/.test(id || ''); }

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

      // ---- admin routes (site owner only) ----
      if (path.startsWith('/api/admin/')) {
        if (!(await adminAuthed(request, env))) return json({ ok: false, error: 'unauthorized' }, 401, origin);

        if (path === '/api/admin/tours' && request.method === 'GET') {
          const list = await env.PORTAL.list({ prefix: 'tour:' });
          const tours = [];
          for (const k of list.keys) {
            const t = sanitizeTour(await env.PORTAL.get(k.name, { type: 'json' }));
            tours.push({ listingId: k.name.slice(5), enabled: t.enabled, rooms: t.rooms.length });
          }
          tours.sort((a, b) => a.listingId.localeCompare(b.listingId));
          return json({ ok: true, tours: tours }, 200, origin);
        }

        if (path === '/api/admin/tour' && request.method === 'GET') {
          const listingId = url.searchParams.get('listingId') || '';
          if (!listingIdOk(listingId)) return json({ ok: false, error: 'validation' }, 400, origin);
          const tour = sanitizeTour(await env.PORTAL.get('tour:' + listingId, { type: 'json' }));
          return json({ ok: true, tour: tour }, 200, origin);
        }
        if (path === '/api/admin/tour' && request.method === 'PUT') {
          let d = null;
          try { d = await request.json(); } catch (e) {}
          const listingId = String((d && d.listingId) || '').trim();
          if (!listingIdOk(listingId)) return json({ ok: false, error: 'validation' }, 400, origin);
          const tour = sanitizeTour(d);
          if (tour.enabled && tour.rooms.length === 0) return json({ ok: false, error: 'no_rooms' }, 400, origin);
          await env.PORTAL.put('tour:' + listingId, JSON.stringify(tour));
          return json({ ok: true, tour: tour }, 200, origin);
        }

        if (path === '/api/admin/panorama' && request.method === 'POST') {
          if (limited(ip, 30, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
          const form = await request.formData().catch(() => null);
          const file = form && form.get('file');
          const listingId = String((form && form.get('listingId')) || '').trim();
          if (!listingIdOk(listingId)) return json({ ok: false, error: 'validation' }, 400, origin);
          if (!file || typeof file.arrayBuffer !== 'function') return json({ ok: false, error: 'validation' }, 400, origin);
          const ctype = file.type || '';
          if (!ctype.startsWith('image/')) return json({ ok: false, error: 'not_image' }, 400, origin);
          const buf = await file.arrayBuffer();
          if (buf.byteLength > MAX_PANO_BYTES || buf.byteLength < 1024) return json({ ok: false, error: 'bad_size' }, 400, origin);
          const id = Date.now().toString(36) + '-' + randHex(6);
          const key = listingId + '/' + id + '.jpg';
          await env.PORTAL.put('pano:' + key, buf);
          const base = new URL(request.url).origin;
          return json({ ok: true, id: id, url: base + '/api/pano/' + key }, 200, origin);
        }

        let m = path.match(/^\/api\/admin\/panorama\/([A-Za-z0-9-]{1,40})\/([A-Za-z0-9-]+)$/);
        if (m && request.method === 'DELETE') {
          const listingId = m[1], panoId = m[2];
          await env.PORTAL.delete('pano:' + listingId + '/' + panoId + '.jpg').catch(() => {});
          // also drop the room referencing it
          const tkey = 'tour:' + listingId;
          const tour = sanitizeTour(await env.PORTAL.get(tkey, { type: 'json' }));
          tour.rooms = tour.rooms.filter(r => r.id !== panoId);
          tour.hotspots = tour.hotspots.filter(h => h.from !== panoId && h.to !== panoId);
          await env.PORTAL.put(tkey, JSON.stringify(tour));
          return json({ ok: true }, 200, origin);
        }

        return json({ ok: false, error: 'not_found' }, 404, origin);
      }

      // ---- public: tour for the main-site viewer ----
      let m = path.match(/^\/api\/tour\/([A-Za-z0-9-]+)$/);
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
