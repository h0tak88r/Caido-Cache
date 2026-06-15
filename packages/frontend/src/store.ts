import { type ScanConfig, type ScanResult } from "backend";
import { reactive } from "vue";

import { type FrontendSDK } from "@/types";

type State = {
  results: ScanResult[];
  logs: string[];
  activeScans: number;
  config: ScanConfig | undefined;
};

export const state = reactive<State>({
  results: [],
  logs: [],
  activeScans: 0,
  config: undefined,
});

const MAX_LOGS = 200;

function pushLog(line: string): void {
  state.logs.unshift(line);
  if (state.logs.length > MAX_LOGS) state.logs.length = MAX_LOGS;
}

function upsertResult(result: ScanResult): void {
  const index = state.results.findIndex(
    (existing) => existing.requestId === result.requestId,
  );
  if (index !== -1) state.results.splice(index, 1);
  state.results.unshift(result);
}

export async function loadConfig(sdk: FrontendSDK): Promise<ScanConfig> {
  if (state.config !== undefined) return state.config;
  const defaults = await sdk.backend.defaults();
  const stored = sdk.storage.get() as Partial<ScanConfig> | undefined;
  state.config = { ...defaults, ...(stored ?? {}) };
  return state.config;
}

export async function saveConfig(
  sdk: FrontendSDK,
  config: ScanConfig,
): Promise<void> {
  state.config = config;
  await sdk.storage.set(config);
}

export async function resetConfig(sdk: FrontendSDK): Promise<ScanConfig> {
  const defaults = await sdk.backend.defaults();
  state.config = defaults;
  await sdk.storage.set(defaults);
  return defaults;
}

export function registerEvents(sdk: FrontendSDK): void {
  sdk.backend.onEvent("wcd:scan-started", (data) => {
    pushLog(`▶ Scanning ${data.host}${data.path}`);
  });
  sdk.backend.onEvent("wcd:scan-progress", (data) => {
    pushLog(`  [${data.sent}] ${data.message}`);
  });
  sdk.backend.onEvent("wcd:scan-finished", (data) => {
    upsertResult(data.result);
    const firm = data.result.findings.filter(
      (f) => f.confidence === "firm",
    ).length;
    const where = `${data.result.host}${data.result.path}`;
    if (data.result.vulnerable) {
      pushLog(`✔ Vulnerable: ${firm} cacheable URL(s) on ${where}`);
    } else if (data.result.findings.length > 0) {
      pushLog(
        `~ Tentative: ${data.result.findings.length} candidate(s) need review on ${where}`,
      );
    } else {
      pushLog(`– Not vulnerable: ${where}`);
    }
  });
  sdk.backend.onEvent("wcd:scan-failed", (data) => {
    pushLog(`✖ Scan failed: ${data.error}`);
  });
}

export async function runScan(
  sdk: FrontendSDK,
  requestId: string,
): Promise<void> {
  const config = await loadConfig(sdk);
  state.activeScans++;
  try {
    const result = await sdk.backend.scan(requestId, config);
    if (result.kind === "Error") {
      sdk.window.showToast(`Web Cache Deception scan failed: ${result.error}`, {
        variant: "error",
      });
      return;
    }
    upsertResult(result.value);
    const scan = result.value;
    const firm = scan.findings.filter((f) => f.confidence === "firm").length;
    if (scan.vulnerable) {
      sdk.window.showToast(
        `Web Cache Deception confirmed — ${firm} cacheable URL(s)`,
        { variant: "warning" },
      );
    } else if (scan.findings.length > 0) {
      sdk.window.showToast(
        `${scan.findings.length} tentative candidate(s) — manual review needed`,
        { variant: "warning" },
      );
    } else {
      sdk.window.showToast(`Not vulnerable — ${scan.reason}`, {
        variant: "info",
      });
    }
  } finally {
    state.activeScans--;
  }
}
