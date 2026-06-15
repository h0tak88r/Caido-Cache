export type Result<T> =
  | { kind: "Ok"; value: T }
  | { kind: "Error"; error: string };

export type Delimiter = {
  value: string;
  label: string;
};

export type ScanConfig = {
  marker: string;
  initialExtensions: string[];
  extraExtensions: string[];
  delimiters: Delimiter[];
  jaroThreshold: number;
  levenThreshold: number;
  maxCompareLength: number;
  delayMs: number;
  authHeaders: string[];
  saveRequests: boolean;
};

export type VariantFinding = {
  delimiter: string;
  delimiterLabel: string;
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
  delimitersTested: string[];
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
  ],
  delimiters: [
    { value: "/", label: "Path segment (/)" },
    { value: ";", label: "Matrix param (;)" },
    { value: "%2f", label: "Encoded slash (%2f)" },
    { value: "%3f", label: "Encoded question mark (%3f)" },
    { value: "%23", label: "Encoded hash (%23)" },
    { value: "\\", label: "Backslash (\\)" },
  ],
  jaroThreshold: 0.8,
  levenThreshold: 200,
  maxCompareLength: 15000,
  delayMs: 150,
  authHeaders: ["Cookie", "Authorization", "X-Api-Key", "X-Auth-Token"],
  saveRequests: true,
};
