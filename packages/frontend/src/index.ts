import { Classic } from "@caido/primevue";
import PrimeVue from "primevue/config";
import { createApp } from "vue";

import { SDKPlugin } from "./plugins/sdk";
import { loadConfig, registerEvents, runScan } from "./store";
import "./styles/index.css";
import type { FrontendSDK } from "./types";
import App from "./views/App.vue";

const PAGE = "/web-cache-deception";
const COMMAND = "web-cache-deception:scan";

type Target = { id: string };

function collectTargets(context: unknown): Target[] {
  const ctx = context as {
    type?: string;
    requests?: Array<{ id: string | number }>;
    request?: { type?: string; id?: string | number };
  };

  if (ctx.type === "RequestRowContext" && ctx.requests !== undefined) {
    return ctx.requests.map((request) => ({ id: String(request.id) }));
  }

  if (
    ctx.type === "RequestContext" &&
    ctx.request !== undefined &&
    ctx.request.type === "RequestFull" &&
    ctx.request.id !== undefined
  ) {
    return [{ id: String(ctx.request.id) }];
  }

  return [];
}

export const init = (sdk: FrontendSDK) => {
  const app = createApp(App);

  app.use(PrimeVue, {
    unstyled: true,
    pt: Classic,
  });

  app.use(SDKPlugin, sdk);

  const root = document.createElement("div");
  Object.assign(root.style, {
    height: "100%",
    width: "100%",
  });
  root.id = `plugin--web-cache-deception`;

  app.mount(root);

  registerEvents(sdk);
  void loadConfig(sdk);

  sdk.navigation.addPage(PAGE, { body: root });
  sdk.sidebar.registerItem("Web Cache Deception", PAGE, {
    icon: "fas fa-bahai",
  });

  sdk.commands.register(COMMAND, {
    name: "Web Cache Deception Test",
    group: "Web Cache Deception",
    run: (context) => {
      const targets = collectTargets(context);
      if (targets.length === 0) {
        sdk.window.showToast(
          "Select one or more requests to run the Web Cache Deception test",
          { variant: "warning" },
        );
        return;
      }

      sdk.navigation.goTo(PAGE);
      sdk.window.showToast(
        `Starting Web Cache Deception scan on ${targets.length} request(s)`,
        { variant: "info" },
      );

      void (async () => {
        for (const target of targets) await runScan(sdk, target.id);
      })();
    },
    when: (context) => collectTargets(context).length > 0,
  });

  sdk.commandPalette.register(COMMAND);
  sdk.shortcuts.register(COMMAND, ["Control", "Shift", "W"]);

  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: COMMAND,
    leadingIcon: "fas fa-bahai",
  });
  sdk.menu.registerItem({
    type: "Request",
    commandId: COMMAND,
    leadingIcon: "fas fa-bahai",
  });
};
