<script setup lang="ts">
import { type ScanResult } from "backend";
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Splitter from "primevue/splitter";
import SplitterPanel from "primevue/splitterpanel";
import Tag from "primevue/tag";
import { computed, ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import { state } from "@/store";

const sdk = useSDK();
const selection = ref<ScanResult | undefined>(undefined);

const current = computed<ScanResult | undefined>(() => {
  if (selection.value !== undefined) {
    const match = state.results.find((r) => r.id === selection.value?.id);
    if (match !== undefined) return match;
  }
  return state.results[0];
});

function copy(text: string): void {
  void navigator.clipboard.writeText(text);
  sdk.window.showToast("Copied to clipboard", { variant: "success" });
}

function fmtTime(ms: number): string {
  return new Date(ms).toLocaleTimeString();
}

type Sev = "danger" | "warn" | "secondary";

function rowSeverity(r: ScanResult): Sev {
  if (r.vulnerable) return "danger";
  return r.findings.length > 0 ? "warn" : "secondary";
}

function rowLabel(r: ScanResult): string {
  if (r.vulnerable) return "VULN";
  return r.findings.length > 0 ? "review" : "ok";
}

function statusLabel(r: ScanResult): string {
  if (r.vulnerable) return "VULNERABLE";
  return r.findings.length > 0 ? "TENTATIVE — REVIEW" : "NOT VULNERABLE";
}
</script>

<template>
  <Splitter class="h-full w-full">
    <SplitterPanel
      :size="42"
      :min-size="25"
      class="flex flex-col gap-2 min-h-0"
    >
      <div class="flex-1 min-h-0 bg-surface-700 rounded p-1">
        <DataTable
          v-model:selection="selection"
          :value="state.results"
          data-key="id"
          selection-mode="single"
          striped-rows
          scrollable
          scroll-height="flex"
          class="h-full"
        >
          <template #empty>
            <div class="p-4 text-center text-surface-300">
              <i class="fas fa-bahai text-2xl mb-2 block" />
              No scans yet. Right-click a request and choose
              <b>Web Cache Deception Test</b>.
            </div>
          </template>

          <Column header="" style="width: 2.5rem">
            <template #body="{ data }">
              <Tag :value="rowLabel(data)" :severity="rowSeverity(data)" />
            </template>
          </Column>
          <Column field="host" header="Host" />
          <Column field="path" header="Path" />
          <Column header="URLs" style="width: 4rem">
            <template #body="{ data }">{{ data.findings.length }}</template>
          </Column>
          <Column header="Time" style="width: 6rem">
            <template #body="{ data }">{{ fmtTime(data.scannedAt) }}</template>
          </Column>
        </DataTable>
      </div>

      <div
        class="bg-surface-700 rounded p-2 overflow-auto"
        style="height: 30%; min-height: 8rem"
      >
        <div class="text-sm font-semibold mb-1 text-surface-200">
          Activity log
        </div>
        <div
          v-for="(line, index) in state.logs"
          :key="index"
          class="text-xs font-mono text-surface-300 whitespace-pre-wrap"
        >
          {{ line }}
        </div>
      </div>
    </SplitterPanel>

    <SplitterPanel :size="58" :min-size="30" class="min-h-0">
      <div class="h-full bg-surface-700 rounded p-3 overflow-auto">
        <div v-if="current === undefined" class="text-surface-300">
          Select a scan to view details.
        </div>

        <div v-else class="flex flex-col gap-3">
          <div class="flex items-center gap-2">
            <Tag
              :value="statusLabel(current)"
              :severity="rowSeverity(current)"
            />
            <Tag v-if="current.vulnerable" value="High" severity="warn" />
            <span class="text-xs text-surface-400">
              {{ current.requestsSent }} requests sent ·
              {{ fmtTime(current.scannedAt) }}
            </span>
          </div>

          <div class="flex items-center gap-2">
            <code class="text-sm break-all"
              >{{ current.method }} {{ current.url }}</code
            >
            <Button
              icon="fas fa-copy"
              size="small"
              text
              @click="copy(current.url)"
            />
          </div>

          <div class="text-sm text-surface-300">{{ current.reason }}</div>

          <div v-if="current.findings.length > 0">
            <div class="text-sm font-semibold mb-1">Cacheable exploit URLs</div>
            <DataTable :value="current.findings" striped-rows class="text-sm">
              <Column header="Conf." style="width: 5rem">
                <template #body="{ data }">
                  <Tag
                    :value="data.confidence === 'firm' ? 'firm' : 'tentative'"
                    :severity="data.confidence === 'firm' ? 'danger' : 'warn'"
                  />
                </template>
              </Column>
              <Column field="technique" header="Technique" />
              <Column field="vector" header="Vector" />
              <Column field="extension" header="Ext" style="width: 3.5rem" />
              <Column header="Exploit URL">
                <template #body="{ data }">
                  <div class="flex items-center gap-1">
                    <code class="break-all text-xs">{{ data.exploitUrl }}</code>
                    <Button
                      icon="fas fa-copy"
                      size="small"
                      text
                      @click="copy(data.exploitUrl)"
                    />
                  </div>
                </template>
              </Column>
              <Column header="Cache" style="width: 5rem">
                <template #body="{ data }">
                  <Tag
                    :value="data.cacheHit ? 'HIT' : '—'"
                    :severity="data.cacheHit ? 'success' : 'secondary'"
                  />
                </template>
              </Column>
              <Column header="Sim." style="width: 4rem">
                <template #body="{ data }">{{
                  data.similarity.toFixed(2)
                }}</template>
              </Column>
            </DataTable>

            <div
              v-for="finding in current.findings"
              :key="finding.exploitUrl"
              class="mt-2"
            >
              <div
                v-if="finding.cacheHeaders.length > 0"
                class="text-xs text-surface-400"
              >
                <span class="font-mono break-all">
                  {{ finding.extension }} →
                  {{ finding.cacheHeaders.join(" · ") }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </SplitterPanel>
  </Splitter>
</template>
