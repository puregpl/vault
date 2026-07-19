/**
 * Vault worker — GitHub sign-in + Cloudflare R2 file operations
 *
 * Auth routes (the browser has no client secret, so the exchange happens here):
 *   POST /exchange { code }          -> { access_token, refresh_token?, expires_in? }
 *   POST /refresh  { refresh_token } -> { access_token, refresh_token, expires_in }
 *
 * File routes (all require an Authorization: Bearer <github token> header;
 * the worker asks GitHub who that token belongs to and checks the allow-list):
 *   GET    /files                 -> { files: [{ key, size, uploaded }], base }
 *   PUT    /files/<key>           -> { key, size }        body = raw file bytes
 *   DELETE /files/<key>           -> { deleted: true }
 *
 * Bindings (wrangler.toml):
 *   BUCKET          R2 bucket
 *   ALLOWED_ORIGIN  exact origin of the Vault page
 *   PUBLIC_BASE     public URL the bucket is served from
 *   ALLOWED_USERS   comma-separated GitHub logins permitted to write
 *
 * Secrets (wrangler secret put ...):
 *   GITHUB_CLIENT_ID
 *   GITHUB_CLIENT_SECRET
 */

export default {
  async fetch(request, env) {
    const origin = env.ALLOWED_ORIGIN || '*';
    const cors = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, PUT, DELETE, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const reqOrigin = request.headers.get('Origin');
    if (origin !== '*' && reqOrigin && reqOrigin !== origin) {
      return json({ error: 'This origin is not allowed to use this worker.' }, 403, cors);
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === '/exchange' || url.pathname === '/refresh') {
        return await handleAuth(request, env, url, cors);
      }
      if (url.pathname === '/files' || url.pathname.startsWith('/files/')) {
        return await handleFiles(request, env, url, cors);
      }
      return json({ error: 'No such route.' }, 404, cors);
    } catch (err) {
      return json({ error: err.message || 'Something went wrong.' }, err.status || 500, cors);
    }
  }
};

/* ------------------------------------------------------------------ auth */

async function handleAuth(request, env, url, cors) {
  if (request.method !== 'POST') {
    return json({ error: 'Use POST for this route.' }, 405, cors);
  }
  const body = await request.json().catch(() => ({}));
  const params = {
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET
  };

  if (url.pathname === '/exchange') {
    if (!body.code) return json({ error: 'No authorization code was sent.' }, 400, cors);
    params.code = body.code;
  } else {
    if (!body.refresh_token) return json({ error: 'No refresh token was sent.' }, 400, cors);
    params.grant_type = 'refresh_token';
    params.refresh_token = body.refresh_token;
  }

  const res = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify(params)
  });
  const data = await res.json();
  if (data.error) return json({ error: data.error_description || data.error }, 400, cors);

  return json({
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_in: data.expires_in
  }, 200, cors);
}

/* ------------------------------------------------- identity + allow-list */

const userCache = new Map();
const CACHE_MS = 5 * 60 * 1000;

async function whoami(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.replace(/^Bearer\s+/i, '').trim();
  if (!token) throw new HttpError(401, 'Sign in to continue.');

  const hit = userCache.get(token);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.login;

  const res = await fetch('https://api.github.com/user', {
    headers: {
      'Authorization': 'Bearer ' + token,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'vault-worker'
    }
  });
  if (!res.ok) throw new HttpError(401, 'That sign-in is no longer valid.');

  const me = await res.json();
  const allowed = (env.ALLOWED_USERS || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

  if (allowed.length && !allowed.includes(me.login.toLowerCase())) {
    throw new HttpError(403, me.login + ' is not on the allow-list for this vault.');
  }

  userCache.set(token, { login: me.login, at: Date.now() });
  return me.login;
}

/* ----------------------------------------------------------------- files */

async function handleFiles(request, env, url, cors) {
  const login = await whoami(request, env);
  const key = decodeURIComponent(url.pathname.replace(/^\/files\/?/, ''));

  if (request.method === 'GET') {
    const listed = await env.BUCKET.list({ limit: 1000 });
    return json({
      files: listed.objects.map(o => ({
        key: o.key,
        size: o.size,
        uploaded: o.uploaded
      })),
      base: env.PUBLIC_BASE || ''
    }, 200, cors);
  }

  if (request.method === 'PUT') {
    if (!key) return json({ error: 'The upload needs a file name.' }, 400, cors);
    if (key.includes('..')) return json({ error: 'That file name is not allowed.' }, 400, cors);

    const object = await env.BUCKET.put(key, request.body, {
      httpMetadata: {
        contentType: request.headers.get('Content-Type') || 'application/octet-stream',
        contentDisposition: 'attachment; filename="' + key.split('/').pop() + '"'
      },
      customMetadata: { uploadedBy: login }
    });
    return json({ key, size: object.size }, 200, cors);
  }

  if (request.method === 'DELETE') {
    if (!key) return json({ error: 'The delete needs a file name.' }, 400, cors);
    await env.BUCKET.delete(key);
    return json({ deleted: true, key }, 200, cors);
  }

  return json({ error: 'That method is not supported here.' }, 405, cors);
}

/* ----------------------------------------------------------------- utils */

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors }
  });
}
