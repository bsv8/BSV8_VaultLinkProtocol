import { test, expect } from "./fixtures.mjs";
import { mkdir, writeFile } from "node:fs/promises";
test("Keymaster Worker ↔ real USB ↔ RocKey product UI and persistent signing policy", async ({
  page,
  context,
}, info) => {
  page.on("console", (m) => {
    if (m.type() === "info" && m.text().startsWith("[RocKey E2E]"))
      console.log(m.text());
  });
  const query = new URLSearchParams({
    vid: process.env.VLP_USB_VID ?? "",
    pid: process.env.VLP_USB_PID ?? "",
    build: process.env.ROCKEY_E2E_EXPECTED_BUILD_ID ?? "",
  });
  await page.goto("/?" + query);
  await page.waitForFunction(() => !!window.rockeyE2E);
  const poolsOnly = process.env.VLP_ROCKEY_DIAGNOSTIC_PAYMENTS === "pools";
  const diagnostic =
    process.env.VLP_ROCKEY_DIAGNOSTIC_PAYMENTS === "1" || poolsOnly;
  const report = await page.evaluate(
    ({ diagnostic, poolsOnly }) =>
      diagnostic
        ? window.rockeyE2E.runPaymentDiagnostics(poolsOnly)
        : window.rockeyE2E.run(),
    { diagnostic, poolsOnly },
  );
  report.browserVersion = context.browser().version();
  report.serialPort = process.env.VLP_SELECTED_SERIAL_PORT;
  report.expectedFirmwareSHA256 =
    process.env.ROCKEY_E2E_FIRMWARE_SHA256 ?? null;
  await mkdir(new URL("../artifacts/", import.meta.url), { recursive: true });
  await writeFile(
    new URL(
      "../artifacts/rockey-product-hardware-report.json",
      import.meta.url,
    ),
    JSON.stringify(report, null, 2) + "\n",
  );
  await info.attach("product-hardware-report", {
    body: JSON.stringify(report, null, 2),
    contentType: "application/json",
  });
  expect(report.status, JSON.stringify(report)).toBe("passed");
  expect(report.hardware).toBe(true);
  expect(report.results).toHaveLength(poolsOnly ? 2 : diagnostic ? 18 : 22);
  expect(report.diagnosticOnly ?? false).toBe(diagnostic);
  expect(report.results.every((r) => r.status === "passed")).toBe(true);
});
