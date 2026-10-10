import { test, expect } from "./fixtures.mjs";
test("product E2E browser page and actual Keymaster Worker start without hardware", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "RocKey 产品固件 E2E" }),
  ).toBeVisible();
  await page.waitForFunction(() => !!window.rockeyE2E);
  expect(await page.evaluate(() => window.rockeyE2E.checkWorker())).toEqual({
    status: "disconnected",
  });
  // 没有设备的运行必须失败；绝不使用软件替身返回硬件通过。
  const report = await page.evaluate(() => window.rockeyE2E.run());
  expect(report.status).toBe("failed");
  expect(report.error).toMatch(/physical USB device/);
  expect(errors).toEqual([]);
});
