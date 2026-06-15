# Changelog

## 1.0.1

- Verified running in Caido v0.57 (loads, scans, and renders results/settings).
- Documentation: detection model, confidence (firm/tentative), and technique
  catalog clarified.

## 1.0.0

Initial release — a Web Cache Deception scanner for Caido, an independent
reimplementation and modernization of PortSwigger's `web-cache-deception-scanner`
Burp extension.

- **Techniques** (all toggleable): path confusion, direct extension, static
  directory (traversal/normalization), static filename.
- **Delimiters:** `/`, `;`, `%2f`, `%3f`, `%23`, `\`, `%00`, `%0a`, `%0d`, `%09`,
  `%3b`, `%2e`, `%20`, `%26`, `//`.
- **Byte-exact probes** via the raw request API (no path re-canonicalization).
- **Caching is proven, not assumed:** a leak candidate is reported as a finding
  only when corroborated by a cache-HIT header, an explicitly cacheable response
  (`Cache-Control: public`/`max-age`/`s-maxage`), or a cache-buster negative
  control; otherwise it is surfaced as tentative for manual review. This
  distinguishes real WCD from broken access control.
- Faithful similarity model (Jaro-Winkler ≥ 0.8 OR Levenshtein ≤ 200, tunable).
- Resilient sends (failed probes are skipped, hard request budget), context-menu
  + command-palette trigger, Caido Findings integration, and a results page with
  a live activity log.
