import { test, expect } from "./fixtures.mjs";
import { writeFile, mkdir } from "node:fs/promises";
// 不跳过不存在的硬件，不用虚拟 serial 成功替身。执行这个入口就必须有真实已授权设备。
test("Web SDK ↔ USB ↔ ESP32 SDK 全自动集成测试", async ({
  page,
  context,
}, testInfo) => {
  const query = new URLSearchParams();
  if (process.env.VLP_USB_VID) query.set("vid", process.env.VLP_USB_VID);
  if (process.env.VLP_USB_PID) query.set("pid", process.env.VLP_USB_PID);
  await page.goto("/?" + query);
  await expect(
    page.getByRole("heading", { name: "VaultLink SDK 集成测试" }),
  ).toBeVisible();
  await page.waitForFunction(() => !!window.vlpE2E);
  const report = await page.evaluate(() => window.vlpE2E.run());
  report.browserVersion = context.browser().version();
  report.browserChannel = process.env.VLP_BROWSER_CHANNEL ?? "msedge";
  report.sdkVersion = "0.2.0-draft.1";
  report.timestamp = new Date().toISOString();
  report.device = {
    serialPort: process.env.VLP_SELECTED_SERIAL_PORT,
    vendorId: Number(process.env.VLP_USB_VID),
    productId: Number(process.env.VLP_USB_PID),
    buildTarget: process.env.VLP_BOARD ?? "m5stack-e2e",
  };
  await mkdir(new URL("../artifacts/", import.meta.url), { recursive: true });
  await writeFile(
    new URL("../artifacts/hardware-report.json", import.meta.url),
    JSON.stringify(report, null, 2) + "\n",
  );
  await testInfo.attach("hardware-report", {
    body: JSON.stringify(report, null, 2),
    contentType: "application/json",
  });
  expect(report.error ?? "", JSON.stringify(report)).toBe("");
  expect(report.status).toBe("passed");
  expect(report.hardware).toBe(true);
  expect(report.results).toHaveLength(20);
});
