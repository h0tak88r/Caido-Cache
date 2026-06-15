import type { SDK } from "caido:plugin";
import {
  Body,
  type Request,
  type RequestSpec,
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

function joinPath(path: string, delimiter: string, suffix: string): string {
  if (delimiter === "/") {
    const base = path.endsWith("/") ? path.slice(0, -1) : path;
    return `${base}/${suffix}`;
  }
  return `${path}${delimiter}${suffix}`;
}

// Builds a GET probe based on the original request, with the marker (and
// optional extension) appended to the path using the given delimiter. The
// original query string and headers are preserved so the application still
// renders the same authenticated page; the body is dropped because Web Cache
// Deception is a GET-cacheability issue.
function buildVariant(
  base: Request,
  delimiter: string,
  marker: string,
  extension: string | undefined,
): RequestSpec {
  const spec = base.toSpec();
  spec.setMethod("GET");
  spec.setBody(new Body(""), { updateContentLength: false });
  for (const header of CONTENT_HEADERS) spec.removeHeader(header);

  const suffix = extension === undefined ? marker : `${marker}.${extension}`;
  spec.setPath(joinPath(base.getPath(), delimiter, suffix));
  return spec;
}

function stripAuth(spec: RequestSpec, authHeaders: string[]): void {
  for (const header of authHeaders) spec.removeHeader(header);
}

const HIT_HEADERS = new Set([
  "x-cache",
  "x-cache-status",
  "cf-cache-status",
  "x-proxy-cache",
  "cache-status",
  "x-drupal-cache",
  "x-varnish-cache",
]);

function cacheEvidence(response: Response): {
  hit: boolean;
  headers: string[];
} {
  const headers = response.getHeaders();
  const found: string[] = [];
  let hit = false;

  for (const name of Object.keys(headers)) {
    const lower = name.toLowerCase();
    const value = (headers[name] ?? []).join(", ");
    if (lower.includes("cache") || lower === "age" || lower === "x-served-by") {
      found.push(`${name}: ${value}`);
    }
    if (HIT_HEADERS.has(lower) && /hit/i.test(value)) hit = true;
    if (lower === "age") {
      const age = parseInt(value, 10);
      if (!Number.isNaN(age) && age > 0) hit = true;
    }
  }

  return { hit, headers: found };
}

function buildDescription(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(
    "The application returns authenticated content for a URL that a caching layer treats as a static file, and that response is then served to unauthenticated users. An attacker can lure a victim into requesting one of the URLs below, then re-request the same URL to read the victim's cached authenticated response.",
  );
  lines.push("");
  lines.push(`**Target:** \`${result.method} ${result.url}\``);
  lines.push("");
  lines.push("**Confirmed exploit URLs:**");
  for (const finding of result.findings) {
    const evidence = finding.cacheHit
      ? ` — cache HIT (${finding.cacheHeaders.join("; ")})`
      : finding.cacheHeaders.length > 0
        ? ` — cache headers: ${finding.cacheHeaders.join("; ")}`
        : "";
    lines.push(
      `- \`${finding.exploitUrl}\` (${finding.delimiterLabel}, similarity ${finding.similarity.toFixed(2)})${evidence}`,
    );
  }
  lines.push("");
  lines.push(
    "**Verification:** for each URL the scanner sent an authenticated request (to prime the cache) followed by an unauthenticated request. The unauthenticated response matched the authenticated content and differed from a normal unauthenticated response, indicating the cache returned the victim's data.",
  );
  lines.push("");
  lines.push(
    "**Remediation:** caches should honor `Cache-Control` headers instead of caching by file extension, and the application should reject or normalize URLs with superfluous path segments or extensions.",
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

  // The bare backend `SDK` type does not carry our event map, so `api.send`
  // would reject our event names. Funnel emits through a single typed wrapper.
  const emit = (event: string, data: unknown): void => {
    (sdk.api.send as (e: string, d: unknown) => void)(event, data);
  };

  let sent = 0;
  const send = async (spec: RequestSpec): Promise<Response | undefined> => {
    if (config.delayMs > 0) await sleep(config.delayMs);
    sent++;
    const payload = await sdk.requests.send(spec, {
      save: config.saveRequests,
    });
    return payload.response;
  };

  const result: ScanResult = {
    id: scanId,
    requestId,
    url: base.getUrl(),
    host: base.getHost(),
    port: base.getPort(),
    tls: base.getTls(),
    path: base.getPath(),
    method: base.getMethod(),
    scannedAt: Date.now(),
    authSensitive: false,
    vulnerable: false,
    reason: "",
    requestsSent: 0,
    delimitersTested: [],
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

  try {
    // 1. Authenticated vs unauthenticated baseline. If they look the same, the
    //    page is not auth-sensitive and caching it leaks nothing of value.
    progress("Fetching authenticated baseline");
    const authSpec = buildVariant(base, "/", marker, undefined);
    authSpec.setPath(base.getPath());
    const authBody = bodyText(await send(authSpec));

    progress("Fetching unauthenticated baseline");
    const unauthSpec = buildVariant(base, "/", marker, undefined);
    unauthSpec.setPath(base.getPath());
    stripAuth(unauthSpec, config.authHeaders);
    const unauthBody = bodyText(await send(unauthSpec));

    if (isSimilar(authBody, unauthBody)) {
      result.requestsSent = sent;
      result.reason =
        "Authenticated and unauthenticated responses are similar — the page is not auth-sensitive, so caching it is not a deception risk.";
      emit(Events.finished, { result });
      return { kind: "Ok", value: result };
    }
    result.authSensitive = true;

    const testExtensions = async (
      delimiter: string,
      delimiterLabel: string,
      extensions: string[],
    ): Promise<VariantFinding[]> => {
      const out: VariantFinding[] = [];
      for (const extension of extensions) {
        progress(`Testing ${delimiter}${marker}.${extension}`);
        const primeSpec = buildVariant(base, delimiter, marker, extension);
        const primeResponse = await send(primeSpec);
        const primeBody = bodyText(primeResponse);

        const fetchSpec = buildVariant(base, delimiter, marker, extension);
        stripAuth(fetchSpec, config.authHeaders);
        const fetchResponse = await send(fetchSpec);
        if (fetchResponse === undefined) continue;
        const fetchBody = bodyText(fetchResponse);

        // Cached & leaking: the unauthenticated fetch returned the primed
        // authenticated content AND differs from a normal unauthenticated
        // response. Either condition alone is not enough.
        const matchesPrime = isSimilar(primeBody, fetchBody);
        const matchesAuth = isSimilar(authBody, fetchBody);
        const matchesUnauth = isSimilar(unauthBody, fetchBody);
        if (!(matchesPrime && matchesAuth && !matchesUnauth)) continue;

        const evidence = cacheEvidence(fetchResponse);
        out.push({
          delimiter,
          delimiterLabel,
          extension,
          exploitUrl: fetchSpec.getUrl(),
          cacheHit: evidence.hit,
          cacheHeaders: evidence.headers,
          similarity: jaroWinkler(
            primeBody.slice(0, config.maxCompareLength),
            fetchBody.slice(0, config.maxCompareLength),
          ),
          primeRequestId: primeResponse?.getId() ?? "0",
          fetchRequestId: fetchResponse.getId(),
        });
      }
      return out;
    };

    for (const delimiter of config.delimiters) {
      result.delimitersTested.push(delimiter.value);

      // 2. Path-append tolerance: does the app ignore the appended segment and
      //    still return the same authenticated page?
      progress(`Checking append tolerance for "${delimiter.label}"`);
      const tolSpec = buildVariant(base, delimiter.value, marker, undefined);
      const tolBody = bodyText(await send(tolSpec));
      if (!isSimilar(authBody, tolBody)) continue;

      // 3. Per-extension cache test, mirroring the original two-tier approach:
      //    probe a few common extensions first, expand only if one is cached.
      const initial = await testExtensions(
        delimiter.value,
        delimiter.label,
        config.initialExtensions,
      );
      result.findings.push(...initial);
      if (initial.length > 0) {
        const extra = await testExtensions(
          delimiter.value,
          delimiter.label,
          config.extraExtensions,
        );
        result.findings.push(...extra);
      }
    }

    result.requestsSent = sent;
    result.vulnerable = result.findings.length > 0;
    result.reason = result.vulnerable
      ? `Confirmed ${result.findings.length} cacheable authenticated URL(s).`
      : "No extension/delimiter combination caused authenticated content to be cached for unauthenticated users.";

    if (result.vulnerable) {
      await sdk.findings.create({
        title: "Web Cache Deception",
        description: buildDescription(result),
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
