# Vault — setup

Two pieces: a static page (`index.html`) and a tiny worker that holds your GitHub
client secret. The worker is required because GitHub's token exchange will not
accept a request that has no secret, and a secret cannot live in browser JavaScript.

Total time: about ten minutes. Everything stays on free tiers.

---

## 1. Publish the page

Push `index.html` to a repo and turn on GitHub Pages (Settings → Pages → deploy from
branch). Note the resulting URL, e.g. `https://yourname.github.io/vault`.

---

## 2. Register a GitHub App

Settings → Developer settings → **GitHub Apps** → New GitHub App.

| Field | Value |
|---|---|
| Name | Vault |
| Homepage URL | your Pages URL |
| Callback URL | your Pages URL, exactly — including any subpath |
| Request user authorization (OAuth) during installation | **on** |
| Expire user authorization tokens | **on** |
| Webhook | **off** |

Permissions → Repository permissions → **Contents: Read and write**.

Under "Where can this app be installed", choose **Only on this account**.

Create it, then:
- copy the **Client ID** (starts `Iv1.` or `Iv23`)
- click **Generate a new client secret** and copy it
- click **Install App** and pick which repos it can touch

> Prefer a session that never expires? Register an **OAuth App** instead
> (Developer settings → OAuth Apps). Its tokens don't lapse at all. The trade-off
> is coarser permissions — the `repo` scope covers every repo you own, not a
> chosen few. The code handles both; it detects which one you used.

---

## 3. Deploy the worker

```bash
cd worker
npx wrangler login
# edit wrangler.toml: set ALLOWED_ORIGIN to your Pages origin
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler deploy
```

Wrangler prints the worker URL, e.g. `https://vault-auth.yourname.workers.dev`.

---

## 4. Wire the page to the worker

Open `index.html`, top of the `<script>` block:

```js
const WORKER    = 'https://vault-auth.yourname.workers.dev';
const CLIENT_ID = 'Iv23liABCDEF...';
```

Commit and push. Done.

---

## How the session behaves

| Auth method | Session length |
|---|---|
| GitHub App | 8-hour token, refreshed silently for 6 months |
| OAuth App | Never expires until revoked |
| Personal token | As long as the token's own expiry |

The page refreshes an App token two minutes before it lapses, so in practice you
sign in once and stop thinking about it. Tokens sit in `localStorage`; sign out
clears them. On a shared machine, use the sign-out button.

---

## Notes on hosting files this way

- The Contents API caps a single upload at roughly 25 MB, because base64 encoding
  inflates the payload. Larger plugin bundles will need Releases or object storage.
- Deleted files remain in git history, so the repo grows and never shrinks.
- Raw links only work from a public repo. Private repos return 404 to anyone
  without a token, which includes your visitors.
- Serving heavy download traffic from a repo runs against GitHub's terms. If this
  grows past personal scale, move the files to Cloudflare R2 — the same UI can
  point at it with a presigned-upload endpoint on this worker.
