export type Result<T> =
  | { kind: "Ok"; value: T }
  | { kind: "Error"; error: string };

export type Delimiter = {
  value: string;
  label: string;
};

type Techniques = {
  pathConfusion: boolean;
  directExtension: boolean;
  staticDirectory: boolean;
  staticFilename: boolean;
};

export type ScanConfig = {
  marker: string;
  initialExtensions: string[];
  extraExtensions: string[];
  delimiters: Delimiter[];
  techniques: Techniques;
  staticDirectories: string[];
  staticTraversals: string[];
  staticFilenames: string[];
  jaroThreshold: number;
  levenThreshold: number;
  maxCompareLength: number;
  delayMs: number;
  authHeaders: string[];
  saveRequests: boolean;
};

export type VariantFinding = {
  technique: string;
  vector: string;
  extension: string;
  exploitUrl: string;
  cacheHit: boolean;
  cacheHeaders: string[];
  similarity: number;
  primeRequestId: string;
  fetchRequestId: string;
};

export type ScanResult = {
  id: string;
  requestId: string;
  url: string;
  host: string;
  port: number;
  tls: boolean;
  path: string;
  method: string;
  scannedAt: number;
  authSensitive: boolean;
  vulnerable: boolean;
  reason: string;
  requestsSent: number;
  techniquesRun: string[];
  findings: VariantFinding[];
};

export const DEFAULT_CONFIG: ScanConfig = {
  marker: "",
  initialExtensions: ["css", "js", "jpg"],
  extraExtensions: [
    "html",
    "gif",
    "png",
    "svg",
    "php",
    "txt",
    "pdf",
    "jsp",
    "asp",
    "ico",
    "woff",
    "woff2",
    "json",
    "avif",
  ],
  // Origin treats the marker as part of the resource; the cache may stop
  // parsing at one of these delimiters and key the response as a static file.
  delimiters: [
    { value: "/", label: "Path segment (/)" },
    { value: ";", label: "Matrix param (;)" },
    { value: "%2f", label: "Encoded slash (%2f)" },
    { value: "%3f", label: "Encoded question mark (%3f)" },
    { value: "%23", label: "Encoded hash (%23)" },
    { value: "\\", label: "Backslash (\\)" },
    { value: "%00", label: "Null byte (%00)" },
    { value: "%0a", label: "Newline (%0a)" },
    { value: "%0d", label: "Carriage return (%0d)" },
    { value: "%09", label: "Tab (%09)" },
    { value: "%3b", label: "Encoded semicolon (%3b)" },
    { value: "%2e", label: "Encoded dot (%2e)" },
    { value: "%20", label: "Space (%20)" },
    { value: "%26", label: "Ampersand (%26)" },
    { value: "//", label: "Double slash (//)" },
  ],
  // Path-normalization payloads for the static-directory technique. The cache
  // keys the URL under the static prefix; the origin resolves the traversal
  // back to the sensitive page. Includes raw, encoded, double-encoded, and
  // semicolon (Tomcat-style) forms.
  staticTraversals: [
    "..%2f",
    "%2e%2e%2f",
    "../",
    "%2e%2e/",
    "%252e%252e%252f",
    "..%2f..%2f",
    "..;/",
  ],
  techniques: {
    pathConfusion: true,
    directExtension: true,
    staticDirectory: true,
    staticFilename: true,
  },
  staticDirectories: [
    "static",
    "assets",
    "resources",
    "media",
    "content",
    "public",
    "cdn",
  ],
  staticFilenames: [
    "robots.txt",
    "index.html",
    "sw.js",
    "favicon.ico",
    "crossdomain.xml",
    "sitemap.xml",
  ],
  jaroThreshold: 0.8,
  levenThreshold: 200,
  maxCompareLength: 15000,
  delayMs: 150,
  authHeaders: ["Cookie", "Authorization", "X-Api-Key", "X-Auth-Token"],
  saveRequests: true,
};
