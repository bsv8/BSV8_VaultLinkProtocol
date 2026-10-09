import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.mjs",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 240000,
  reporter: [
    ["list"],
    [
      "json",
      {
        outputFile: fileURLToPath(
          new URL("../artifacts/browser-report.json", import.meta.url),
        ),
      },
    ],
    ["html", { outputFolder: "../artifacts/playwright-report", open: "never" }],
  ],
  use: {
    browserName: "chromium",
    channel: process.env.VLP_BROWSER_CHANNEL ?? "msedge",
    headless: true,
    ...(process.env.VLP_BROWSER_EXECUTABLE
      ? {
          launchOptions: { executablePath: process.env.VLP_BROWSER_EXECUTABLE },
        }
      : {}),
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "node integration/web/server.mjs",
    url: "http://127.0.0.1:4173",
    cwd: fileURLToPath(new URL("../../", import.meta.url)),
    reuseExistingServer: false,
    timeout: 30000,
  },
  outputDir: "../artifacts/playwright-results",
});
