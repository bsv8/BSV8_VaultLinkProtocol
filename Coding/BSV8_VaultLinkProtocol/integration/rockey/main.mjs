import { WebSerialTransport } from "../../src/transport.ts";
import { RocKeyTestLink } from "./transport.mjs";
import { KeymasterRocKeyJourney } from "keymaster-rockey-e2e-client";
import {
  TEST_PUBLIC_KEY,
  enterTestPin,
  enroll,
  runJourney,
  waitFor,
} from "./journey.mjs";
const rows = document.querySelector("#results"),
  status = document.querySelector("#status");
const ids = [
  new URLSearchParams(location.search).get("vid"),
  new URLSearchParams(location.search).get("pid"),
];
let running = false,
  selected;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function open() {
  if (!navigator.serial) throw Error("Web Serial unavailable");
  const ports = (await navigator.serial.getPorts()).filter((p) => {
    const i = p.getInfo();
    return (
      (ids[0] === null || i.usbVendorId === Number(ids[0])) &&
      (ids[1] === null || i.usbProductId === Number(ids[1]))
    );
  });
  if (ports.length !== 1)
    throw Error("Exactly one authorized physical USB device is required");
  selected = ports[0];
  return new RocKeyTestLink(await WebSerialTransport.open(selected));
}
async function ready(link) {
  let s = await link.status();
  console.info("[RocKey E2E] device ready: " + JSON.stringify(s));
  const expectedBuild = new URLSearchParams(location.search).get("build");
  if (expectedBuild && s.buildId !== expectedBuild)
    throw Error("device firmware build does not match prepared test image");
  if (s.firmware !== "rockey-product-e2e-v1" || !s.isolated || s.selftestFailed)
    throw Error("Product test firmware/storage/self-test not ready");
  if (!s.initialized) {
    await link.control([3], 20000);
    s = await link.status();
  }
  if (s.publicKey !== TEST_PUBLIC_KEY)
    throw Error(
      "Existing E2E wallet is not the fixed public test wallet; no overwrite performed",
    );
  if (!s.unlocked) {
    if (Number(s.screen) === 19) await link.press(2); // 正常错误页“返回”按钮
    await waitFor(
      () => link.status(),
      (s) => Number(s.screen) === 1,
      "lock screen",
      600000,
    );
    console.info("[RocKey E2E] entering normal PIN");
    await enterTestPin(link);
  }
}
async function run() {
  if (running) throw Error("test-already-running");
  running = true;
  rows.textContent = "";
  let link, journey, paymentResults = [];
  const extra = [];
  const append = (r) => {
    const li = document.createElement("li");
    li.textContent = `${r.status}: ${r.name}${r.error ? " — " + r.error : ""}`;
    rows.append(li);
    console.info("[RocKey E2E] " + r.status + ": " + r.name);
  };
  try {
    status.textContent = "Connecting real RocKey product test firmware…";
    link = await open();
    await ready(link);
    console.info("[RocKey E2E] initial unlock complete");
    // 错 PIN 与重启等待：经过正常 UI，重启后仍必须等待，不调用 Unlock API。
    await link.control([4]);
    await link.close();
    await sleep(1800);
    link = await open();
    await waitFor(
      () => link.status(),
      (s) => Number(s.screen) === 1,
      "reboot lock",
    );
    const old = Number((await link.status()).failCount);
    console.info("[RocKey E2E] entering wrong PIN");
    await enterTestPin(link, true);
    let failed = await link.status();
    if (Number(failed.failCount) !== old + 1 || failed.unlocked)
      throw Error("wrong PIN did not persist failure");
    await link.control([4]);
    await link.close();
    await sleep(1800);
    link = await open();
    failed = await link.status();
    if (Number(failed.failCount) !== old + 1 || failed.unlocked)
      throw Error("reboot reset PIN failure");
    await ready(link);
    extra.push({
      name: "wrong PIN, persistent failure and restart lock",
      status: "passed",
    });
    append(extra.at(-1));
    journey = new KeymasterRocKeyJourney();
    await enroll(link, journey, { deny: true });
    await journey.close();
    journey = undefined;
    await sleep(1000);
    link = await open();
    await ready(link);
    extra.push({
      name: "device button-path pairing denial rejects Keymaster enrollment",
      status: "passed",
    });
    append(extra.at(-1));
    journey = new KeymasterRocKeyJourney();
    const document = await enroll(link, journey);
    extra.push({
      name: "Keymaster Worker enrollment verifies matching codes and key possession",
      status: "passed",
    });
    append(extra.at(-1));
    const report = await runJourney(link, journey, append);
    paymentResults = report.results;
    // 软件重启检验持久化；真实断电另列人工验收，不能用 restart 冒充。
    const channels = await journey.payment({ action: "list" }),
      session = await journey.rpc("session-read", { id: report.runId });
    await link.control([4]);
    await journey.close();
    journey = undefined;
    await sleep(1800);
    link = await open();
    await ready(link);
    journey = new KeymasterRocKeyJourney();
    await enroll(link, journey);
    const restored = await journey.payment({ action: "list" }),
      oldSession = await journey.rpc("session-read", { id: report.runId });
    if (
      JSON.stringify(channels) !== JSON.stringify(restored) ||
      oldSession.active ||
      BigInt(oldSession.used) !== BigInt(session.used)
    )
      throw Error("restart lost spending configuration/closed session total");
    extra.push({
      name: "ESP32 restart preserves channels and closed session ledger",
      status: "passed",
    });
    append(extra.at(-1));
    report.results = [...extra, ...report.results];
    report.document = document;
    report.timestamp = new Date().toISOString();
    report.device = await link.status();
    report.manualPending = [
      "release firmware physical buttons and screen",
      "physical power cut during commit",
      "bidirectional migration hardware acceptance",
    ];
    status.textContent = `Passed ${report.results.length} physical USB checks; manual release checks remain.`;
    return report;
  } catch (e) {
    status.textContent = "Failed: " + e.message;
    return {
      status: "failed",
      hardware: true,
      error: e.message,
      stack: e.stack,
      results: [...extra, ...(e.results ?? paymentResults)],
      timestamp: new Date().toISOString(),
    };
  } finally {
    await journey?.close().catch(() => {});
    await link?.close().catch(() => {});
    running = false;
  }
}
// 定位付款链路时只执行真实付款场景；报告明确标为诊断，不替代完整 22 项验收。
async function runPaymentDiagnostics(poolsOnly = false) {
  let link, journey;
  try {
    link = await open();
    await ready(link);
    journey = new KeymasterRocKeyJourney();
    await enroll(link, journey);
    const report = await runJourney(
      link,
      journey,
      (r) => console.info("[RocKey E2E] " + r.status + ": " + r.name),
      { poolsOnly },
    );
    return { ...report, diagnosticOnly: true };
  } catch (e) {
    return {
      status: "failed",
      hardware: true,
      diagnosticOnly: true,
      error: e.message,
      stack: e.stack,
      results: e.results ?? [],
    };
  } finally {
    await journey?.close().catch(() => {});
    await link?.close().catch(() => {});
  }
}
document.querySelector("#authorize").onclick = async () => {
  try {
    await navigator.serial.requestPort();
    status.textContent = "USB device authorized";
  } catch (e) {
    status.textContent = e.message;
  }
};
document.querySelector("#run").onclick = () => void run();
window.rockeyE2E = {
  run,
  runPaymentDiagnostics,
  async checkWorker() {
    const j = new KeymasterRocKeyJourney();
    try {
      return await j.rpc("state");
    } finally {
      await j.close();
    }
  },
};
