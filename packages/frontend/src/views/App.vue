<script setup lang="ts">
import Button from "primevue/button";
import { ref } from "vue";

import Results from "./Results.vue";
import Settings from "./Settings.vue";

import { state } from "@/store";

const tab = ref<"results" | "settings">("results");
</script>

<template>
  <div class="h-full flex flex-col gap-2 p-2">
    <div class="flex items-center gap-3">
      <span class="text-lg font-semibold">Web Cache Deception Scanner</span>
      <span v-if="state.activeScans > 0" class="text-sm text-surface-300">
        <i class="fas fa-spinner fa-spin" /> {{ state.activeScans }} running
      </span>
      <div class="flex-1" />
      <Button
        label="Results"
        icon="fas fa-list"
        size="small"
        :outlined="tab !== 'results'"
        @click="tab = 'results'"
      />
      <Button
        label="Settings"
        icon="fas fa-cog"
        size="small"
        :outlined="tab !== 'settings'"
        @click="tab = 'settings'"
      />
    </div>

    <div class="flex-1 min-h-0">
      <Results v-if="tab === 'results'" />
      <Settings v-else />
    </div>
  </div>
</template>
