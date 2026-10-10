import { test as base, expect } from "@playwright/test";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { browserOptions } from "../runner/browser-options.mjs";
export const test = base.extend({
  context: async ({ playwright }, use) => {
    const dir = await mkdtemp(path.join(tmpdir(), "rockey-product-e2e-"));
    const ids = [process.env.VLP_USB_VID, process.env.VLP_USB_PID].map((x) =>
      x === undefined ? null : Number(x),
    );
    if (
      ids.some(
        (x) => x !== null && (!Number.isInteger(x) || x < 0 || x > 65535),
      )
    )
      throw Error("invalid-usb-id");
    const allowed = ids.every((x) => x !== null)
      ? [
          {
            devices: [{ vendor_id: ids[0], product_id: ids[1] }],
            urls: ["http://127.0.0.1:4175"],
          },
        ]
      : [];
    let context;
    try {
      await mkdir(path.join(dir, "Default"));
      await writeFile(
        path.join(dir, "Local State"),
        JSON.stringify({
          managed: { serial_allow_usb_devices_for_urls: allowed },
        }),
      );
      context = await playwright.chromium.launchPersistentContext(dir, {
        ...browserOptions,
        baseURL: "http://127.0.0.1:4175",
      });
      await use(context);
    } finally {
      try {
        await context?.close();
      } finally {
        // A failed browser shutdown must not retain a large disposable profile.
        await rm(dir, { recursive: true, force: true });
      }
    }
  },
});
export { expect };
