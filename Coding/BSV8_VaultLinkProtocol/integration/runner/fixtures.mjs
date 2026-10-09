import { test as base, expect } from "@playwright/test";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { browserOptions } from "./browser-options.mjs";
// 独立测试资料目录，不写系统/用户日常浏览器的策略。
// Chromium SerialPolicyAllowedPorts 读取 Local State 的这个已注册 pref：
// https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/serial/serial_policy_allowed_ports.cc
// https://chromium.googlesource.com/chromium/src/+/main/chrome/common/pref_names.h
// 这是对真实浏览器的预授权配置，不替换 navigator.serial/getPorts。硬件枚举失败即测试失败。
export const test = base.extend({
  context: async ({ playwright }, use) => {
    const dir = await mkdtemp(path.join(tmpdir(), "vlp-edge-e2e-"));
    const ids = [process.env.VLP_USB_VID, process.env.VLP_USB_PID].map((v) =>
      v === undefined ? null : Number(v),
    );
    for (const id of ids)
      if (id !== null && (!Number.isInteger(id) || id < 0 || id > 65535))
        throw Error("invalid USB ID");
    const allowed = ids.every((id) => id !== null)
      ? [
          {
            devices: [{ vendor_id: ids[0], product_id: ids[1] }],
            urls: ["http://127.0.0.1:4173"],
          },
        ]
      : [];
    await mkdir(path.join(dir, "Default"), { recursive: true });
    await writeFile(
      path.join(dir, "Local State"),
      JSON.stringify({
        managed: { serial_allow_usb_devices_for_urls: allowed },
      }),
    );
    let context;
    try {
      context = await playwright.chromium.launchPersistentContext(dir, {
        ...browserOptions,
        baseURL: "http://127.0.0.1:4173",
      });
      await use(context);
    } finally {
      // Trace/screenshot 由 Playwright 的统一 fixture 管理，避免两次停止遮蔽原始失败。
      try {
        if (context) await context.close();
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    }
  },
});
export { expect };
