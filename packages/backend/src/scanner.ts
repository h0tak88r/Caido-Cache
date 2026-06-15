import { Buffer } from "buffer";

import type { SDK } from "caido:plugin";
import {
  Body,
  type RequestSpec,
  type RequestSpecRaw,
  type Response,
} from "caido:utils";

import { jaroWinkler, similar } from "./similarity";
import {
  DEFAULT_CONFIG,
  type Result,
  type ScanConfig,
  type ScanResult,
  type VariantFinding,
} from "./types";

const Events = {
  started: "wcd:scan-started",
  progress: "wcd:scan-progress",
  finished: "wcd:scan-finished",
  failed: "wcd:scan-failed",
} as const;

const CONTENT_HEADERS = ["Content-Length", "Content-Type", "Transfer-Encoding"];

// A plain-ASCII path the parsed RequestSpec will not re-encode. We set it as
// the path, serialize to raw bytes, then splice in the real (possibly
// malformed) payload so the exact bytes reach the wire — see buildRawProbe.
const PATH_PLACEHOLDER = "/__wcd_path_placeholder__";
const CACHE_BUSTER_KEY = "wcdcb";

const HIT_HEADERS = new Set([
  "x-cache",
  "x-cache-status",
  "cf-cache-status",
  "x-proxy-cache",
  "cache-status",
  "x-drupal-cache",
  "x-varnish-cache",
]);

const sleep = (ms: number): Promise<void> =>
  // eslint-disable-next-line compat/compat -- backend runs in QuickJS, not a browser
  new Promise((resolve) => setTimeout(resolve, ms));

function randomToken(length: number): string {
  let token = "";
  while (token.length < length) token += Math.random().toString(36).slice(2);
  return token.slice(0, length);
}

function bodyText(response: Response | undefined): string {
  if (response === undefined) return "";
  const body = response.getBody();
  return body === undefined ? "" : body.toText();
}

function stripTrailingSlash(path: string): string {
  return path.endsWith("/") && path.length > 1 ? path.slice(0, -1) : path;
}

function cacheEvidence(response: Response): {
  hit: boolean;
  cacheable: boolean;
  headers: string[];
} {
  const headers = response.getHeaders();
  const found: string[] = [];
  let hit = false;
  let cacheable = false;

  for (const name of Object.keys(headers)) {
    const lower = name.toLowerCase();
    const value = (headers[name] ?? []).join(", ");
    if (
      lower.includes("cache") ||
      lower === "age" ||
      lower === "expires" ||
      lower === "x-served-by"
    ) {
      found.push(`${name}: ${value}`);
    }
    // Definitive: the response was served FROM a cache.
    if (HIT_HEADERS.has(lower) && /hit/i.test(value)) hit = true;
    if (lower === "age") {
      const age = parseInt(value, 10);
      if (!Number.isNaN(age) && age >= 0) hit = true;
    }
    // Cacheability: the response is explicitly marked storable. Combined with a
    // leak candidate this corroborates caching independently of the cache key,
    // covering caches that ignore the query string.
    if (lower === "cache-control") {
      const directives = value.toLowerCase();
      if (!directives.includes("no-store") && !directives.includes("private")) {
        // Match s-maxage (shared cache — the one that performs WCD) and max-age
        // independently; either being positive means a cache may store this.
        const positive = (re: RegExp) => {
          const m = re.exec(directives);
          return m !== null && parseInt(m[1] ?? "0", 10) > 0;
        };
        if (
          directives.includes("public") ||
          positive(/s-maxage=(\d+)/) ||
          positive(/max-age=(\d+)/)
        ) {
          cacheable = true;
        }
      }
    }
  }

  return { hit, cacheable, headers: found };
}

function buildDescription(result: ScanResult, firm: VariantFinding[]): string {
  const lines: string[] = [];
  lines.push(
    "The application returns authenticated content for a URL that a caching layer treats as a static file, and that response is then served to unauthenticated users. An attacker can lure a victim into requesting one of the URLs below, then re-request the same URL to read the victim's cached authenticated response.",
  );
  lines.push("");
  lines.push(`**Target:** \`${result.method} ${result.url}\``);
  lines.push("");
  lines.push("**Confirmed exploit URLs:**");
  for (const finding of firm) {
    const evidence = finding.cacheHit
      ? ` — cache HIT (${finding.cacheHeaders.join("; ")})`
      : finding.cacheHeaders.length > 0
        ? ` — cacheable response (${finding.cacheHeaders.join("; ")})`
        : " — confirmed via cache-buster control (cache-keyed, not access control)";
    lines.push(
      `- [${finding.technique} · ${finding.vector}] \`${finding.exploitUrl}\` (similarity ${finding.similarity.toFixed(2)})${evidence}`,
    );
  }
  lines.push("");
  lines.push(
    "**Verification:** for each URL the scanner sent an authenticated request (priming the cache), then the same URL unauthenticated (returning the primed content), then an unauthenticated request with a cache-busting query string. Caching is confirmed when the cache-busted request returns the public page while the plain request returns the authenticated content — or when the response carries a cache-HIT header.",
  );
  lines.push("");
  lines.push(
    "**Remediation:** caches should honor `Cache-Control` headers instead of caching by file extension or path prefix, and the application should reject or normalize URLs with superfluous path segments, delimiters, or extensions.",
  );
  return lines.join("\n");
}

export async function scan(
  sdk: SDK,
  requestId: string,
  partial?: Partial<ScanConfig>,
): Promise<Result<ScanResult>> {
  const config: ScanConfig = { ...DEFAULT_CONFIG, ...(partial ?? {}) };
  const marker =
    config.marker.length > 0 ? config.marker : `wcd${randomToken(6)}`;
  const scanId = `${requestId}-${randomToken(4)}`;

  const stored = await sdk.requests.get(requestId);
  if (stored === undefined) {
    return { kind: "Error", error: `Request ${requestId} not found` };
  }
  const base = stored.request;
  const basePath = base.getPath();

  // The bare backend `SDK` type does not carry our event map, so `api.send`
  // would reject our event names. Funnel emits through a single typed wrapper.
  const emit = (event: string, data: unknown): void => {
    (sdk.api.send as (e: string, d: unknown) => void)(event, data);
  };

  let sent = 0;
  let failures = 0;
  let capped = false;
  // A single timed-out/failed probe must not abort the scan or discard the
  // findings already collected — treat it as "this variant did not leak".
  const send = async (
    spec: RequestSpec | RequestSpecRaw,
  ): Promise<Response | undefined> => {
    if (sent >= config.maxRequests) {
      capped = true;
      return undefined;
    }
    if (config.delayMs > 0) await sleep(config.delayMs);
    sent++;
    try {
      const payload = await sdk.requests.send(spec, {
        save: config.saveRequests,
      });
      return payload.response;
    } catch {
      failures++;
      return undefined;
    }
  };

  // Build a byte-exact GET probe. RequestSpec.setPath() feeds a *parsed* path
  // model that would re-encode payloads like `%2f`, `%00`, `\`, or `%252e`, so
  // we set an inert placeholder, serialize to raw bytes, and splice the literal
  // payload into the request line. Headers/host/query come from the original
  // request; the body is dropped (WCD is a GET-cacheability issue).
  const buildRawProbe = (
    path: string,
    unauthenticated: boolean,
    extraQuery?: string,
  ): RequestSpecRaw => {
    const spec = base.toSpec();
    spec.setMethod("GET");
    spec.setBody(new Body(""), { updateContentLength: false });
    for (const header of CONTENT_HEADERS) spec.removeHeader(header);
    if (unauthenticated) {
      for (const header of config.authHeaders) spec.removeHeader(header);
    }
    const origQuery = base.getQuery();
    const query =
      extraQuery !== undefined
        ? origQuery.length > 0
          ? `${origQuery}&${extraQuery}`
          : extraQuery
        : origQuery;
    spec.setQuery(query);
    spec.setPath(PATH_PLACEHOLDER);

    const raw = spec.getRaw();
    const text = Buffer.from(raw.getRaw()).toString("latin1");
    raw.setRaw(
      Buffer.from(
        text.replace(PATH_PLACEHOLDER, () => path),
        "latin1",
      ),
    );
    return raw;
  };

  const scheme = base.getTls() ? "https" : "http";
  const defaultPort = base.getTls() ? 443 : 80;
  const authority =
    base.getPort() === defaultPort
      ? base.getHost()
      : `${base.getHost()}:${base.getPort()}`;
  const probeUrl = (path: string): string => {
    const query = base.getQuery();
    return `${scheme}://${authority}${path}${query.length > 0 ? `?${query}` : ""}`;
  };

  const result: ScanResult = {
    id: scanId,
    requestId,
    url: base.getUrl(),
    host: base.getHost(),
    port: base.getPort(),
    tls: base.getTls(),
    path: basePath,
    method: base.getMethod(),
    scannedAt: Date.now(),
    authSensitive: false,
    vulnerable: false,
    reason: "",
    requestsSent: 0,
    techniquesRun: [],
    findings: [],
  };

  emit(Events.started, {
    id: scanId,
    requestId,
    host: result.host,
    path: result.path,
  });

  const isSimilar = (a: string, b: string) =>
    similar(
      a,
      b,
      config.jaroThreshold,
      config.levenThreshold,
      config.maxCompareLength,
    );

  const progress = (message: string) =>
    emit(Events.progress, { id: scanId, message, sent });

  const tail = () =>
    `${capped ? ` Request budget (${config.maxRequests}) reached; scan truncated.` : ""}${failures > 0 ? ` ${failures} probe(s) failed (network/timeout) and were skipped.` : ""}`;

  try {
    // 1. Authenticated vs unauthenticated baseline. If they look the same, the
    //    page is not auth-sensitive and caching it leaks nothing of value.
    progress("Fetching authenticated baseline");
    const authResponse = await send(buildRawProbe(basePath, false));
    progress("Fetching unauthenticated baseline");
    const unauthResponse = await send(buildRawProbe(basePath, true));

    // A failed baseline must not be mistaken for two identical (empty) bodies,
    // which would wrongly report "not auth-sensitive" and mask a real target.
    if (authResponse === undefined || unauthResponse === undefined) {
      const error = `Could not establish a baseline — ${failures} probe(s) failed. The target may be unreachable or blocking requests.`;
      result.requestsSent = sent;
      emit(Events.failed, { id: scanId, requestId, error });
      return { kind: "Error", error };
    }

    const authBody = bodyText(authResponse);
    const unauthBody = bodyText(unauthResponse);

    if (isSimilar(authBody, unauthBody)) {
      result.requestsSent = sent;
      result.reason =
        "Authenticated and unauthenticated responses are similar — the page is not auth-sensitive, so caching it is not a deception risk." +
        tail();
      emit(Events.finished, { result });
      return { kind: "Ok", value: result };
    }
    result.authSensitive = true;

    // Confirm a real cache leak (not server-side access control). Prime the
    // cache authenticated, fetch the same URL unauthenticated; if that returns
    // the authenticated content, distinguish caching from access control with a
    // cache-busting control request (different cache key → hits the origin).
    const evaluate = async (
      path: string,
      technique: string,
      vector: string,
      extension: string,
    ): Promise<VariantFinding | undefined> => {
      const primeResponse = await send(buildRawProbe(path, false));
      const primeBody = bodyText(primeResponse);
      if (primeResponse === undefined || !isSimilar(authBody, primeBody)) {
        return undefined;
      }

      const fetchResponse = await send(buildRawProbe(path, true));
      if (fetchResponse === undefined) return undefined;
      const fetchBody = bodyText(fetchResponse);

      const candidate =
        isSimilar(primeBody, fetchBody) &&
        isSimilar(authBody, fetchBody) &&
        !isSimilar(unauthBody, fetchBody);
      if (!candidate) return undefined;

      const evidence = cacheEvidence(fetchResponse);

      // Negative control: same URL, unauthenticated, with a cache-busting query
      // param. If caching is the cause AND the cache keys on the query, this
      // bypasses the cache and returns the public page; if the origin itself
      // serves authed content to anon (access control / route confusion), it
      // still returns the authed page. NOTE: a cache that ignores the query
      // string in its key defeats this control — such cases rely instead on the
      // cache-HIT / cacheability header signals below, and otherwise remain
      // "tentative" for manual review.
      const controlResponse = await send(
        buildRawProbe(path, true, `${CACHE_BUSTER_KEY}=${randomToken(6)}`),
      );
      let controlConfirms = false;
      if (controlResponse !== undefined) {
        const controlBody = bodyText(controlResponse);
        controlConfirms =
          isSimilar(unauthBody, controlBody) &&
          !isSimilar(authBody, controlBody);
      }

      // Firm = caching corroborated by any query-independent signal (served
      // from cache, explicitly cacheable) or the cache-buster control.
      const confidence: "firm" | "tentative" =
        evidence.hit || evidence.cacheable || controlConfirms
          ? "firm"
          : "tentative";

      return {
        technique,
        vector,
        extension,
        exploitUrl: probeUrl(path),
        confidence,
        cacheHit: evidence.hit,
        cacheHeaders: evidence.headers,
        similarity: jaroWinkler(
          primeBody.slice(0, config.maxCompareLength),
          fetchBody.slice(0, config.maxCompareLength),
        ),
        primeRequestId: primeResponse.getId(),
        fetchRequestId: fetchResponse.getId(),
      };
    };

    const probeExtensions = async (
      makePath: (suffix: string) => string,
      technique: string,
      vector: string,
    ): Promise<void> => {
      const initial: VariantFinding[] = [];
      for (const ext of config.initialExtensions) {
        const finding = await evaluate(
          makePath(`${marker}.${ext}`),
          technique,
          vector,
          ext,
        );
        if (finding !== undefined) initial.push(finding);
      }
      result.findings.push(...initial);
      if (initial.length === 0) return;
      for (const ext of config.extraExtensions) {
        const finding = await evaluate(
          makePath(`${marker}.${ext}`),
          technique,
          vector,
          ext,
        );
        if (finding !== undefined) result.findings.push(finding);
      }
    };

    const gateExt = config.initialExtensions[0] ?? "css";

    // Technique 1 — path confusion: /path<delimiter>marker.ext
    if (config.techniques.pathConfusion) {
      result.techniquesRun.push("Path confusion");
      for (const delimiter of config.delimiters) {
        const makePath = (suffix: string) => {
          const root = delimiter.value.startsWith("/")
            ? stripTrailingSlash(basePath)
            : basePath;
          return `${root}${delimiter.value}${suffix}`;
        };

        // Cheap gate using a representative real exploit path (with extension):
        // if the origin does not return the authed page here, skip the rest.
        progress(`Path confusion: testing "${delimiter.label}"`);
        const gateBody = bodyText(
          await send(buildRawProbe(makePath(`${marker}.${gateExt}`), false)),
        );
        if (!isSimilar(authBody, gateBody)) continue;

        await probeExtensions(makePath, "Path confusion", delimiter.label);
      }
    }

    // Technique 2 — direct extension: /path.ext (no delimiter, no marker)
    if (config.techniques.directExtension) {
      result.techniquesRun.push("Direct extension");
      progress("Testing direct extension (/path.ext)");
      const root = stripTrailingSlash(basePath);
      const initial: VariantFinding[] = [];
      for (const ext of config.initialExtensions) {
        const finding = await evaluate(
          `${root}.${ext}`,
          "Direct extension",
          "no delimiter",
          ext,
        );
        if (finding !== undefined) initial.push(finding);
      }
      result.findings.push(...initial);
      if (initial.length > 0) {
        for (const ext of config.extraExtensions) {
          const finding = await evaluate(
            `${root}.${ext}`,
            "Direct extension",
            "no delimiter",
            ext,
          );
          if (finding !== undefined) result.findings.push(finding);
        }
      }
    }

    // Technique 3 — static filename: /path/<cached-filename>
    if (config.techniques.staticFilename) {
      result.techniquesRun.push("Static filename");
      const root = stripTrailingSlash(basePath);
      for (const filename of config.staticFilenames) {
        progress(`Static filename: ${filename}`);
        const finding = await evaluate(
          `${root}/${filename}`,
          "Static filename",
          filename,
          filename.split(".").pop() ?? "",
        );
        if (finding !== undefined) result.findings.push(finding);
      }
    }

    // Technique 4 — static directory: /<dir>/<traversal><path> (the cache keys
    // it under the cached directory; the origin resolves the traversal back to
    // the sensitive page).
    if (config.techniques.staticDirectory) {
      result.techniquesRun.push("Static directory");
      const rest = basePath.replace(/^\/+/, "");
      for (const dir of config.staticDirectories) {
        progress(`Static directory: /${dir}/`);
        for (const traversal of config.staticTraversals) {
          const finding = await evaluate(
            `/${dir}/${traversal}${rest}`,
            "Static directory",
            `/${dir}/ ${traversal}`,
            "",
          );
          if (finding !== undefined) result.findings.push(finding);
        }
      }
    }

    const firm = result.findings.filter((f) => f.confidence === "firm");
    const tentative = result.findings.length - firm.length;
    result.requestsSent = sent;
    result.vulnerable = firm.length > 0;
    result.reason =
      firm.length > 0
        ? `Confirmed ${firm.length} cacheable authenticated URL(s)${tentative > 0 ? `, plus ${tentative} tentative` : ""}.`
        : tentative > 0
          ? `${tentative} tentative candidate(s) returned authenticated content but caching could not be confirmed — likely server-side access control rather than cache deception. Verify manually.`
          : "No technique caused authenticated content to be cached for unauthenticated users.";
    result.reason += tail();

    if (firm.length > 0) {
      await sdk.findings.create({
        title: "Web Cache Deception",
        description: buildDescription(result, firm),
        reporter: "Web Cache Deception Scanner",
        dedupeKey: `wcd:${result.host}:${result.port}:${result.path}`,
        request: base,
      });
    }

    emit(Events.finished, { result });
    return { kind: "Ok", value: result };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    result.requestsSent = sent;
    emit(Events.failed, { id: scanId, requestId, error: message });
    return { kind: "Error", error: message };
  }
}
