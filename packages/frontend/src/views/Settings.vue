<script setup lang="ts">
import { type Delimiter, type ScanConfig } from "backend";
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import InputNumber from "primevue/inputnumber";
import InputText from "primevue/inputtext";
import { computed, onMounted, ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import { loadConfig, resetConfig, saveConfig } from "@/store";

const sdk = useSDK();

const CATALOG: Delimiter[] = [
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
];

const TECHNIQUES: { key: keyof ScanConfig["techniques"]; label: string }[] = [
  { key: "pathConfusion", label: "Path confusion (/path;marker.css)" },
  { key: "directExtension", label: "Direct extension (/path.css)" },
  { key: "staticDirectory", label: "Static directory (/static/..%2fpath)" },
  { key: "staticFilename", label: "Static filename (/path/robots.txt)" },
];

const form = ref<ScanConfig | undefined>(undefined);

onMounted(async () => {
  form.value = { ...(await loadConfig(sdk)) };
});

const initialExt = computed<string>({
  get: () => form.value?.initialExtensions.join(", ") ?? "",
  set: (value) => {
    if (form.value !== undefined)
      form.value.initialExtensions = parseList(value);
  },
});

const extraExt = computed<string>({
  get: () => form.value?.extraExtensions.join(", ") ?? "",
  set: (value) => {
    if (form.value !== undefined) form.value.extraExtensions = parseList(value);
  },
});

const authHeaders = computed<string>({
  get: () => form.value?.authHeaders.join(", ") ?? "",
  set: (value) => {
    if (form.value !== undefined) form.value.authHeaders = parseList(value);
  },
});

const staticDirectories = computed<string>({
  get: () => form.value?.staticDirectories.join(", ") ?? "",
  set: (value) => {
    if (form.value !== undefined)
      form.value.staticDirectories = parseList(value);
  },
});

const staticFilenames = computed<string>({
  get: () => form.value?.staticFilenames.join(", ") ?? "",
  set: (value) => {
    if (form.value !== undefined) form.value.staticFilenames = parseList(value);
  },
});

function parseList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function isDelimiterActive(value: string): boolean {
  return form.value?.delimiters.some((d) => d.value === value) ?? false;
}

function toggleDelimiter(delimiter: Delimiter, checked: boolean): void {
  if (form.value === undefined) return;
  const without = form.value.delimiters.filter(
    (d) => d.value !== delimiter.value,
  );
  form.value.delimiters = checked ? [...without, delimiter] : without;
}

async function onSave(): Promise<void> {
  if (form.value === undefined) return;
  await saveConfig(sdk, { ...form.value });
  sdk.window.showToast("Settings saved", { variant: "success" });
}

async function onReset(): Promise<void> {
  form.value = { ...(await resetConfig(sdk)) };
  sdk.window.showToast("Settings reset to defaults", { variant: "info" });
}
</script>

<template>
  <div v-if="form !== undefined" class="h-full overflow-auto">
    <div class="flex flex-col gap-4 max-w-2xl">
      <div>
        <label class="block text-sm font-semibold mb-1">Techniques</label>
        <p class="text-xs text-surface-400 mb-2">
          Which Web Cache Deception techniques to run.
        </p>
        <div class="grid grid-cols-2 gap-2">
          <div
            v-for="technique in TECHNIQUES"
            :key="technique.key"
            class="flex items-center gap-2"
          >
            <Checkbox
              v-model="form.techniques[technique.key]"
              binary
              :input-id="`tech-${technique.key}`"
            />
            <label :for="`tech-${technique.key}`" class="text-sm">
              {{ technique.label }}
            </label>
          </div>
        </div>
      </div>

      <div>
        <label class="block text-sm font-semibold mb-1">
          Initial extensions
        </label>
        <p class="text-xs text-surface-400 mb-1">
          Tested first. If any is cached, the extra list is also tested.
        </p>
        <InputText v-model="initialExt" class="w-full" />
      </div>

      <div>
        <label class="block text-sm font-semibold mb-1">Extra extensions</label>
        <InputText v-model="extraExt" class="w-full" />
      </div>

      <div>
        <label class="block text-sm font-semibold mb-1">Path delimiters</label>
        <p class="text-xs text-surface-400 mb-2">
          Ways to append the cache-buster to the URL.
        </p>
        <div class="grid grid-cols-2 gap-2">
          <div
            v-for="delimiter in CATALOG"
            :key="delimiter.value"
            class="flex items-center gap-2"
          >
            <Checkbox
              :model-value="isDelimiterActive(delimiter.value)"
              binary
              :input-id="`delim-${delimiter.value}`"
              @update:model-value="
                (v) => toggleDelimiter(delimiter, v === true)
              "
            />
            <label :for="`delim-${delimiter.value}`" class="text-sm">
              {{ delimiter.label }}
            </label>
          </div>
        </div>
      </div>

      <div>
        <label class="block text-sm font-semibold mb-1">
          Static directories
        </label>
        <p class="text-xs text-surface-400 mb-1">
          Cached path prefixes for the <code>/static/..%2fpath</code> technique.
        </p>
        <InputText v-model="staticDirectories" class="w-full" />
      </div>

      <div>
        <label class="block text-sm font-semibold mb-1">
          Static filenames
        </label>
        <p class="text-xs text-surface-400 mb-1">
          Cached filenames appended as <code>/path/&lt;name&gt;</code>.
        </p>
        <InputText v-model="staticFilenames" class="w-full" />
      </div>

      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="block text-sm font-semibold mb-1">
            Jaro-Winkler threshold
          </label>
          <InputNumber
            v-model="form.jaroThreshold"
            :min="0"
            :max="1"
            :step="0.05"
            :min-fraction-digits="2"
            :max-fraction-digits="2"
            show-buttons
            class="w-full"
          />
        </div>
        <div>
          <label class="block text-sm font-semibold mb-1">
            Levenshtein threshold
          </label>
          <InputNumber v-model="form.levenThreshold" :min="0" class="w-full" />
        </div>
        <div>
          <label class="block text-sm font-semibold mb-1">
            Max compare length
          </label>
          <InputNumber
            v-model="form.maxCompareLength"
            :min="500"
            :step="500"
            class="w-full"
          />
        </div>
        <div>
          <label class="block text-sm font-semibold mb-1">
            Delay between requests (ms)
          </label>
          <InputNumber
            v-model="form.delayMs"
            :min="0"
            :step="50"
            class="w-full"
          />
        </div>
      </div>

      <div>
        <label class="block text-sm font-semibold mb-1">
          Authentication headers to strip
        </label>
        <p class="text-xs text-surface-400 mb-1">
          Removed to simulate the unauthenticated attacker request.
        </p>
        <InputText v-model="authHeaders" class="w-full" />
      </div>

      <div class="flex items-center gap-2">
        <Checkbox v-model="form.saveRequests" binary input-id="save-req" />
        <label for="save-req" class="text-sm">
          Save probe requests to the project (visible in Search)
        </label>
      </div>

      <div class="flex gap-2">
        <Button label="Save" icon="fas fa-save" @click="onSave" />
        <Button
          label="Reset to defaults"
          icon="fas fa-rotate-left"
          outlined
          @click="onReset"
        />
      </div>
    </div>
  </div>
</template>
