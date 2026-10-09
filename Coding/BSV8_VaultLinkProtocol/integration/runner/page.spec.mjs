import { test, expect } from "./fixtures.mjs";
// 页面启动测试不连接硬件；不运行或冒充硬件集成序列。
test("真实浏览器加载 SDK 测试页和 Web Serial API", async ({
  page,
  context,
}, testInfo) => {
  testInfo.annotations.push({
    type: "browser-version",
    description: context.browser().version(),
  });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "VaultLink SDK 集成测试" }),
  ).toBeVisible();
  await page.waitForFunction(() => !!window.vlpE2E);
  expect(await page.evaluate(() => typeof navigator.serial?.getPorts)).toBe(
    "function",
  );
  await expect(
    page.getByRole("button", { name: "运行全部测试" }),
  ).toBeEnabled();
  await expect(page.getByRole("button", { name: "下载报告" })).toBeDisabled();
});

test("独立浏览器资料实际读取 USB 串口预授权配置", async ({ page }) => {
  await page.goto("chrome://local-state/");
  const text = await page.locator("body").innerText();
  const prefs = JSON.parse(text);
  // 此页面返回真实浏览器注册的 pref 值，不能只检查我们写出的 JSON 文件。
  const local = prefs["Local State"] ?? prefs;
  const actual =
    local.managed?.serial_allow_usb_devices_for_urls ??
    local["managed.serial_allow_usb_devices_for_urls"];
  const ids = [process.env.VLP_USB_VID, process.env.VLP_USB_PID].map((v) =>
    v === undefined ? null : Number(v),
  );
  const expected = ids.every((id) => id !== null)
    ? [
        {
          devices: [{ vendor_id: ids[0], product_id: ids[1] }],
          urls: ["http://127.0.0.1:4173"],
        },
      ]
    : [];
  expect(actual?.value ?? actual).toEqual(expected);
});
