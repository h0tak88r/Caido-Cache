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

### Modernization over the original

- Multiple path-confusion **delimiters** (`/`, `;`, `%2f`, `%3f`, `%23`, `\`, and
  optional `%00` / `%0a`), not just `/`.
- Configurable **extension list** (two-tier, like the original).
- Stronger confirmation logic (prime-vs-fetch-vs-unauth comparison) to cut false
  positives, plus cache-header corroboration.
- Faithful similarity model: Jaro-Winkler ≥ 0.8 **OR** Levenshtein ≤ 200, with
  tunable thresholds and input caps for performance.

All probes are forced to **GET** and a configurable inter-request delay keeps the
scan well-behaved.

## Settings

The **Settings** tab lets you tune the extension lists, active delimiters,
similarity thresholds, max compared body length, request delay, the auth headers
stripped for the unauthenticated request, and whether probes are saved to the
project. Settings persist via the plugin storage.

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
