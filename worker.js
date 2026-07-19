/**
 * Vault auth worker
 *
 * Holds the GitHub client secret so the browser never sees it.
 * Two routes:
 *   POST /exchange { code }          -> { access_token, refresh_token?, expires_in? }
 *   POST /refresh  { refresh_token } -> { access_token, refresh_token, expires_in }
 *
 * Secrets (wrangler secret put ...):
 *   GITHUB_CLIENT_ID
 *   GITHUB_CLIENT_SECRET
 * Vars (wrangler.toml):
 *   ALLOWED_ORIGIN — the exact origin of your Pages site
 */

export default {
  async fetch(request, env) {
    const origin = env.ALLOWED_ORIGIN || '*';
    const cors = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // Only serve the origin we were configured for.
    const reqOrigin = request.headers.get('Origin');
    if (origin !== '*' && reqOrigin && reqOrigin !== origin) {
      return json({ error: 'origin_not_allowed' }, 403, cors);
    }

    if (request.method !== 'POST') {
      return json({ error: 'method_not_allowed' }, 405, cors);
    }

    const url = new URL(request.url);
    const body = await request.json().catch(() => ({}));

    const params = { client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET };

    if (url.pathname === '/exchange') {
      if (!body.code) return json({ error: 'missing_code' }, 400, cors);
      params.code = body.code;
    } else if (url.pathname === '/refresh') {
      if (!body.refresh_token) return json({ error: 'missing_refresh_token' }, 400, cors);
      params.grant_type = 'refresh_token';
      params.refresh_token = body.refresh_token;
    } else {
      return json({ error: 'not_found' }, 404, cors);
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
};

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors }
  });
}
