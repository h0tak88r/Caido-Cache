# Web Cache Deception Scanner for Caido

A Caido plugin that tests requests for **Web Cache Deception (WCD)** — when a
caching layer stores an authenticated user's response under a static-looking URL
and then serves it to anonymous users.

This is an independent reimplementation and modernization of the PortSwigger Burp
extension [`web-cache-deception-scanner`](https://github.com/PortSwigger/web-cache-deception-scanner),
ported to Caido's frontend + backend plugin SDK.

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
- Stronger confirmation logic: a finding requires the unauthenticated fetch to
  match the primed authenticated content **and** differ from a normal
  unauthenticated response (prime ≈ fetch ≈ auth, fetch ≉ unauth) — cuts false
  positives the original would raise.
- Faithful similarity model: Jaro-Winkler ≥ 0.8 **OR** Levenshtein ≤ 200, with
  tunable thresholds and input caps for performance.
- Cache-header corroboration (`X-Cache`, `CF-Cache-Status`, `Age`, …).

All probes are forced to **GET** and a configurable inter-request delay keeps the
scan well-behaved. Each technique can be disabled in Settings to limit request
volume.

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
