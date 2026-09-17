
// _worker.js — серверная логика Cloudflare Pages
// Все запросы к /api/* идут сюда. Статика раздаётся автоматически.

const COOKIE_NAME = 'admin_session';
const SESSION_TTL = 60 * 60 * 24 * 7; // 7 дней

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith('/api/')) {
      try {
        if (path === '/api/login'    && request.method === 'POST') return await login(request, env);
        if (path === '/api/logout'   && request.method === 'POST') return logout();
        if (path === '/api/me'       && request.method === 'GET')  return await me(request, env);
        if (path === '/api/posts'    && (request.method === 'GET' || request.method === 'POST')) return await posts(request, env);
        if (path === '/api/services' && (request.method === 'GET' || request.method === 'POST')) return await services(request, env);
        if (path === '/api/wallpapers' && (request.method === 'GET' || request.method === 'POST')) return await wallpapers(request, env);
        return json({ error: 'Not found' }, 404);
      } catch (e) {
        return json({ error: e.message || 'Ошибка сервера' }, 500);
      }
    }

    // Всё остальное — статические файлы (index.html, media/, imoby/)
    return env.ASSETS.fetch(request);
  }
};

/* ============ JWT (подпись/проверка токена) ============ */
function b64url(str) {
  return btoa(str).replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlBytes(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return atob(s);
}
async function hmacKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}
async function signJWT(payload, secret) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const data = header + '.' + body;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return data + '.' + b64urlBytes(new Uint8Array(sig));
}
async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const key = await hmacKey(secret);
    const sigBytes = Uint8Array.from(b64urlDecode(parts[2]), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      'HMAC', key, sigBytes,
      new TextEncoder().encode(parts[0] + '.' + parts[1])
    );
    if (!valid) return null;
    const payload = JSON.parse(b64urlDecode(parts[1]));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

/* ============ Хелперы ============ */
function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders }
  });
}
function getCookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  const found = raw.split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return found ? found.slice(name.length + 1) : null;
}
async function requireAuth(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token || !env.JWT_SECRET) return null;
  return await verifyJWT(token, env.JWT_SECRET);
}

/* ============ Handlers ============ */

// POST /api/login  { password }
async function login(request, env) {
  const body = await request.json();
  const password = body.password || '';
  if (!env.ADMIN_PASSWORD) return json({ error: 'ADMIN_PASSWORD не настроен на сервере' }, 500);
  if (!env.JWT_SECRET)     return json({ error: 'JWT_SECRET не настроен на сервере' }, 500);
  if (password !== env.ADMIN_PASSWORD) return json({ error: 'Неверный пароль' }, 401);

  const token = await signJWT(
    { sub: 'admin', exp: Math.floor(Date.now() / 1000) + SESSION_TTL },
    env.JWT_SECRET
  );
  return json({ success: true }, 200, {
    'Set-Cookie': `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}`
  });
}

// POST /api/logout
function logout() {
  return json({ success: true }, 200, {
    'Set-Cookie': `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
  });
}

// GET /api/me
async function me(request, env) {
  const session = await requireAuth(request, env);
  return json({ authenticated: !!session });
}

// GET /api/posts   → все посты (публично)
// POST /api/posts  { action: 'add'|'update'|'delete', post? , id? }  → только админ
async function posts(request, env) {
  if (request.method === 'GET') {
    const list = (await env.ROOTSQL_KV.get('posts', { type: 'json' })) || [];
    return json(list);
  }
  const session = await requireAuth(request, env);
  if (!session) return json({ error: 'Не авторизован' }, 401);

  const body = await request.json();
  let list = (await env.ROOTSQL_KV.get('posts', { type: 'json' })) || [];

  if (body.action === 'add') {
    list.push({
      id: crypto.randomUUID(),
      title: String(body.post.title || ''),
      description: String(body.post.description || ''),
      media: body.post.media || null,
      mediaType: body.post.mediaType || null,
      createdAt: Date.now()
    });
  } else if (body.action === 'update') {
    const i = list.findIndex(p => p.id === body.post.id);
    if (i !== -1) {
      list[i] = { ...list[i], ...body.post };
    }
  } else if (body.action === 'delete') {
    list = list.filter(p => p.id !== body.id);
  } else {
    return json({ error: 'Неизвестное действие' }, 400);
  }

  await env.ROOTSQL_KV.put('posts', JSON.stringify(list));
  return json({ success: true, posts: list });
}

// GET /api/services, POST /api/services — то же самое
async function services(request, env) {
  if (request.method === 'GET') {
    const list = (await env.ROOTSQL_KV.get('services', { type: 'json' })) || [];
    return json(list);
  }
  const session = await requireAuth(request, env);
  if (!session) return json({ error: 'Не авторизован' }, 401);

  const body = await request.json();
  let list = (await env.ROOTSQL_KV.get('services', { type: 'json' })) || [];

  if (body.action === 'add') {
    list.push({
      id: crypto.randomUUID(),
      name: String(body.service.name || ''),
      description: String(body.service.description || ''),
      price: String(body.service.price || ''),
      media: body.service.media || null,
      createdAt: Date.now()
    });
  } else if (body.action === 'update') {
    const i = list.findIndex(s => s.id === body.service.id);
    if (i !== -1) {
      list[i] = { ...list[i], ...body.service };
    }
  } else if (body.action === 'delete') {
    list = list.filter(s => s.id !== body.id);
  } else {
    return json({ error: 'Неизвестное действие' }, 400);
  }

  await env.ROOTSQL_KV.put('services', JSON.stringify(list));
  return json({ success: true, services: list });
}

// GET /api/wallpapers — обои
// POST /api/wallpapers { action: 'set'|'remove', theme, type, data? }
async function wallpapers(request, env) {
  if (request.method === 'GET') {
    const data = (await env.ROOTSQL_KV.get('wallpapers', { type: 'json' })) || { light: {}, dark: {} };
    return json(data);
  }
  const session = await requireAuth(request, env);
  if (!session) return json({ error: 'Не авторизован' }, 401);

  const body = await request.json();
  let data = (await env.ROOTSQL_KV.get('wallpapers', { type: 'json' })) || { light: {}, dark: {} };
  if (!data.light) data.light = {};
  if (!data.dark)  data.dark  = {};

  const theme = body.theme === 'light' ? 'light' : 'dark';
  const type  = body.type; // 'live' | 'static' | 'sound'

  if (!['live', 'static', 'sound'].includes(type)) {
    return json({ error: 'Неверный тип обоев' }, 400);
  }

  if (body.action === 'set') {
    data[theme][type] = body.data || null;
  } else if (body.action === 'remove') {
    delete data[theme][type];
  } else {
    return json({ error: 'Неизвестное действие' }, 400);
  }

  await env.ROOTSQL_KV.put('wallpapers', JSON.stringify(data));
  return json({ success: true, wallpapers: data });
                              }
