# Lab: Source Map Exposure

> **One line:** Shipping a JavaScript source map to production hands an attacker
> your original, un-minified source code — comments, internal variable names,
> dead code, and any secrets you "hid" in the front end — straight from their
> browser.

This lab is intentionally vulnerable. It is part of [MAUL](../../../README.md).

---

## Why this matters

Modern front-ends ship **minified** JavaScript (`app.min.js`) — unreadable,
short variable names, no comments. Developers assume "nobody can read minified
code, so it's basically private." So they leave things in the source: TODOs,
internal hostnames, feature-flag logic, debug back doors, even tokens.

A **source map** (`app.min.js.map`) is a developer-convenience file that maps
the minified code back to the original. Browsers download it automatically when
DevTools is open. Crucially, the map contains a `sourcesContent` field holding
**the entire original source as plain text**.

So if the `.map` is reachable on your web server, the "private" minified code
is fully readable by anyone — including the comments you'd never want a
stranger to see.

---

## What's in this lab

| File | Role |
|------|------|
| `app.src.js`     | The **original source** (readable). Contains the secret. |
| `app.min.js`     | The **minified bundle** that ships to the browser. Looks innocuous. |
| `app.min.js.map` | The **source map** — the leak. Reconstructs `app.src.js`. |
| `build.sh`       | Rebuilds `app.min.js` + `app.min.js.map` from `app.src.js` (esbuild). |

The source hardcodes a `DEBUG_BYPASS_TOKEN` and an `INTERNAL_DEBUG_ENDPOINT`
(`/api/internal/debug-config`). The backend honors that token with **no other
auth** and returns fake DB creds, an OpenAI key, internal hostnames, and the
sim password.

---

## Run it

```bash
docker-compose up        # from the repo root
# then open http://localhost:8000
```

(Or run the API directly — the static files are served at `/static/...`.)

---

## Exploit it

### 1. Look at what ships (looks safe)

```bash
curl http://localhost:8000/static/js/app.min.js
```

Minified, mangled names, no comments. Note the last line:

```js
//# sourceMappingURL=app.min.js.map
```

That comment is the breadcrumb.

### 2. Pull the source map (the leak)

```bash
curl -s http://localhost:8000/static/js/app.min.js.map | python -m json.tool
```

The `sourcesContent` array contains the **entire original `app.src.js`** —
including the `TODO(dev): REMOVE BEFORE LAUNCH` comment, the
`DEBUG_BYPASS_TOKEN`, and the internal endpoint path.

### 3. Or do it the way a real attacker does — in the browser

1. Open `http://localhost:8000`
2. Open DevTools → **Sources** tab
3. Under the page's scripts you'll see **`app.src.js`** reconstructed, readable,
   with all comments intact. (DevTools resolves the map automatically.)

### 4. Use the recovered secret

The source revealed a token and a hidden endpoint. No login required:

```bash
curl http://localhost:8000/api/internal/debug-config \
  -H "X-Debug-Token: maul-dev-bypass-7c4e1f90"
```

```json
{
  "database_url": "postgresql://maul:maul_pw@db:5432/maul",
  "openai_api_key": "sk-PROJ-FAKE-...",
  "internal_hosts": ["maul-internal.lan", "ci-runner.maul-internal.lan"],
  "note": "If you reached this without logging in, a source map leaked the token."
}
```

Full chain: **public `.map` → recovered token + path → unauthenticated config dump.**

---

## How to fix it

The bug is not "we used source maps" — they're great in development. The bug is
**publishing them to a public web root** (and trusting minification as secrecy).

### Don't ship `.map` files publicly

Disable source-map *emission* for production builds, or generate them and keep
them out of the deployed web root (upload them to your error-tracker — e.g.
Sentry — instead).

| Tool | Setting |
|------|---------|
| **esbuild** | omit `--sourcemap`, or use `--sourcemap=external` and don't deploy the `.map` |
| **Vite / Rollup** | `build.sourcemap: false` (default) |
| **webpack** | `devtool: false` in production config |
| **Create React App** | `GENERATE_SOURCEMAP=false` env var at build |
| **Next.js** | `productionBrowserSourceMaps: false` (the default) |
| **Angular CLI** | `"sourceMap": false` in the production build options |

### Defense in depth

- Block `*.map` at the CDN / reverse proxy (e.g. return 404 for `\.map$`).
- **Never** put secrets in front-end code. Anything the browser can run, a user
  can read — minified or not. The source map just makes it convenient.
- Remove debug back doors and dev-only endpoints before launch; don't rely on
  obscurity.
- Scan your deployed origin for exposed maps (e.g. request your JS bundles and
  follow the `sourceMappingURL` comment).

---

## Rebuild

```bash
./build.sh        # regenerates app.min.js + app.min.js.map from app.src.js
```
