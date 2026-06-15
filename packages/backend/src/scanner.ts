import type { SDK } from "caido:plugin";
import { Body, type RequestSpec, type Response } from "caido:utils";

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
      `- [${finding.technique} · ${finding.vector}] \`${finding.exploitUrl}\` (similarity ${finding.similarity.toFixed(2)})${evidence}`,
    );
  }
  lines.push("");
  lines.push(
    "**Verification:** for each URL the scanner sent an authenticated request (to prime the cache) followed by an unauthenticated request. The unauthenticated response matched the authenticated content and differed from a normal unauthenticated response, indicating the cache returned the victim's data.",
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
  const send = async (spec: RequestSpec): Promise<Response | undefined> => {
    if (config.delayMs > 0) await sleep(config.delayMs);
    sent++;
    const payload = await sdk.requests.send(spec, {
      save: config.saveRequests,
    });
    return payload.response;
  };

  // Build a GET probe at `path`, preserving the original headers/query so the
  // app still renders the same authenticated page. The body is dropped because
  // Web Cache Deception is a GET-cacheability issue.
  const buildProbe = (path: string, unauthenticated: boolean): RequestSpec => {
    const spec = base.toSpec();
    spec.setMethod("GET");
    spec.setBody(new Body(""), { updateContentLength: false });
    for (const header of CONTENT_HEADERS) spec.removeHeader(header);
    spec.setPath(path);
    if (unauthenticated) {
      for (const header of config.authHeaders) spec.removeHeader(header);
    }
    return spec;
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

  try {
    // 1. Authenticated vs unauthenticated baseline. If they look the same, the
    //    page is not auth-sensitive and caching it leaks nothing of value.
    progress("Fetching authenticated baseline");
    const authBody = bodyText(await send(buildProbe(basePath, false)));

    progress("Fetching unauthenticated baseline");
    const unauthBody = bodyText(await send(buildProbe(basePath, true)));

    if (isSimilar(authBody, unauthBody)) {
      result.requestsSent = sent;
      result.reason =
        "Authenticated and unauthenticated responses are similar — the page is not auth-sensitive, so caching it is not a deception risk.";
      emit(Events.finished, { result });
      return { kind: "Ok", value: result };
    }
    result.authSensitive = true;

    // Unified leak check: prime the cache authenticated, then fetch the exact
    // same URL unauthenticated. A leak requires the origin to serve the
    // sensitive page for this URL (prime ≈ auth) AND the unauthenticated fetch
    // to return that primed content (fetch ≈ prime ≈ auth) while differing from
    // a normal unauthenticated response (fetch ≉ unauth).
    const evaluate = async (
      path: string,
      technique: string,
      vector: string,
      extension: string,
    ): Promise<VariantFinding | undefined> => {
      const primeResponse = await send(buildProbe(path, false));
      const primeBody = bodyText(primeResponse);
      if (!isSimilar(authBody, primeBody)) return undefined;

      const fetchResponse = await send(buildProbe(path, true));
      if (fetchResponse === undefined) return undefined;
      const fetchBody = bodyText(fetchResponse);

      const leaks =
        isSimilar(primeBody, fetchBody) &&
        isSimilar(authBody, fetchBody) &&
        !isSimilar(unauthBody, fetchBody);
      if (!leaks) return undefined;

      const evidence = cacheEvidence(fetchResponse);
      return {
        technique,
        vector,
        extension,
        exploitUrl: buildProbe(path, true).getUrl(),
        cacheHit: evidence.hit,
        cacheHeaders: evidence.headers,
        similarity: jaroWinkler(
          primeBody.slice(0, config.maxCompareLength),
          fetchBody.slice(0, config.maxCompareLength),
        ),
        primeRequestId: primeResponse?.getId() ?? "0",
        fetchRequestId: fetchResponse.getId(),
      };
    };

    // Two-tier extension probing: test a few common extensions; only if one is
    // cached do we test the larger list (mirrors the original Burp extension).
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

        // Cheap gate: if appending the marker changes the page, the origin is
        // not ignoring the suffix for this delimiter — skip its extensions.
        progress(`Path confusion: testing "${delimiter.label}"`);
        const tolBody = bodyText(
          await send(buildProbe(makePath(marker), false)),
        );
        if (!isSimilar(authBody, tolBody)) continue;

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

    // Technique 4 — static directory: /<dir>/..%2f<path> (normalization gap:
    // the cache keys it under the cached directory, the origin resolves the
    // traversal back to the sensitive page).
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

    result.requestsSent = sent;
    result.vulnerable = result.findings.length > 0;
    result.reason = result.vulnerable
      ? `Confirmed ${result.findings.length} cacheable authenticated URL(s).`
      : "No technique caused authenticated content to be cached for unauthenticated users.";

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
