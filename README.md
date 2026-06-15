# Web Cache Deception Scanner for Caido

A Caido plugin that tests requests for **Web Cache Deception (WCD)** — when a
caching layer stores an authenticated user's response under a static-looking URL
and then serves it to anonymous users.

This is an independent reimplementation and modernization of the PortSwigger Burp
extension [`web-cache-deception-scanner`](https://github.com/PortSwigger/web-cache-deception-scanner),
ported to Caido's frontend + backend plugin SDK.

> Verified running in Caido v0.57 — loads, scans real targets, and renders the
> results and settings UI.

## What it does

Right-click a request → **Web Cache Deception Test** (or run it from the command
palette / `Ctrl+Shift+W`). For each selected request the backend:

1. **Auth baseline.** Sends the request authenticated and unauthenticated. If the
   two responses are similar, the page is not auth-sensitive and the scan stops —
   caching it leaks nothing.
2. **Append tolerance.** For each configured path delimiter, appends a random
   cache-buster (e.g. `/account/wcdXXXXXX`) authenticated and checks the app still
   returns the same authenticated page.
3. **Cache confirmation.** For each tolerated delimiter and file extension, primes
   the cache with an authenticated request, then fetches the same URL
   unauthenticated. It reports a finding only when the unauthenticated response
   **matches the primed authenticated content and differs from a normal
   unauthenticated response** — i.e. the cache leaked the victim's data. Cache
   headers (`X-Cache`, `CF-Cache-Status`, `Age`, …) are captured as corroborating
   evidence.

Confirmed results create a Caido **Finding** (`Web Cache Deception`, High) listing
the working exploit URLs, and appear in the plugin's **Results** page with the
request/response evidence.

### Techniques (all toggleable)

| Technique | Probe | Example |
|---|---|---|
| **Path confusion** | append `<delimiter>marker.<ext>` | `/account;wcd123.css` |
| **Direct extension** | append `.<ext>` to the resource | `/account.css` |
| **Static directory** | traversal back through a cached prefix | `/static/..%2faccount` |
| **Static filename** | append a cached filename | `/account/robots.txt` |

**Delimiters tested by default:** `/`, `;`, `%2f`, `%3f`, `%23`, `\`, `%00`, `%0a`,
`%0d`, `%09`, `%3b`, `%2e`, `%20`, `%26`.

**Static directories:** `static`, `assets`, `resources`, `media`, `content`,
`public`, `cdn`. **Static filenames:** `robots.txt`, `index.html`, `sw.js`,
`favicon.ico`, `crossdomain.xml`, `sitemap.xml`.

### Detection model (vs. the original Burp extension)

- Two-tier, configurable **extension list** (same idea as the original).
- **Byte-exact probes.** Malformed paths (`%2f`, `%00`, `%0a`, `%252e`, `\`) are
  spliced into the raw request line, so the cache/origin see the exact bytes
  rather than a re-encoded path.
- **Caching is proven, not assumed.** A leak candidate (unauthenticated fetch ≈
  primed authenticated content, ≉ normal unauthenticated response) is only
  reported as **firm** when caching is corroborated by a cache-HIT header
  (`X-Cache`, `CF-Cache-Status`, `Age`), an explicitly cacheable response
  (`Cache-Control: public/max-age`), or a **cache-buster negative control** (an
  anonymous request with an extra query param returns the public page while the
  plain URL leaks). This distinguishes real WCD from plain broken access control.
  - Candidates without caching corroboration are surfaced as **tentative —
    review** (e.g. a cache that ignores the query string *and* sends no cache
    headers cannot be auto-confirmed remotely; verify manually). Only **firm**
    results create a Caido Finding.
- Faithful similarity model: Jaro-Winkler ≥ 0.8 **OR** Levenshtein ≤ 200, with
  tunable thresholds and input caps for performance.

All probes are forced to **GET**; a failed/timed-out probe is skipped (it never
aborts the scan), a configurable inter-request delay and a hard request budget
keep the scan well-behaved, and each technique can be disabled in Settings.

## Settings

The **Settings** tab lets you toggle techniques, tune the extension lists, active
delimiters, static directories/filenames, similarity thresholds, max compared body
length, request delay, the auth headers stripped for the unauthenticated request,
and whether probes are saved to the project. Settings persist via the plugin
storage.

## Development

```bash
pnpm install
pnpm typecheck   # tsc + vue-tsc
pnpm lint
pnpm build       # → dist/plugin_package.zip
pnpm watch       # hot reload with the Caido Devtools plugin
```

Install `dist/plugin_package.zip` in Caido via **Plugins → Install from file**.

## Layout

```
packages/backend   scan engine (similarity, WCD logic, finding creation)
packages/frontend  Vue 3 + PrimeVue UI (page, command, context menu, settings)
```

## License

MIT
