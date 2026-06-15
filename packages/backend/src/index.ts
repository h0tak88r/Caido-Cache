import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";

import { scan } from "./scanner";
import { DEFAULT_CONFIG, type ScanConfig, type ScanResult } from "./types";

export type {
  ScanConfig,
  ScanResult,
  VariantFinding,
  Delimiter,
  Result,
} from "./types";

function defaults(_sdk: SDK): ScanConfig {
  return DEFAULT_CONFIG;
}

export type BackendEvents = DefineEvents<{
  "wcd:scan-started": (data: {
    id: string;
    requestId: string;
    host: string;
    path: string;
  }) => void;
  "wcd:scan-progress": (data: {
    id: string;
    message: string;
    sent: number;
  }) => void;
  "wcd:scan-finished": (data: { result: ScanResult }) => void;
  "wcd:scan-failed": (data: {
    id: string;
    requestId: string;
    error: string;
  }) => void;
}>;

export type API = DefineAPI<{
  scan: typeof scan;
  defaults: typeof defaults;
}>;

export function init(sdk: SDK<API, BackendEvents>) {
  sdk.api.register("scan", scan);
  sdk.api.register("defaults", defaults);
}
