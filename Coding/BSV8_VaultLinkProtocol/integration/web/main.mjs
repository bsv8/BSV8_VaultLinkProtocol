import {
  WebSerialTransport,
  connectHost,
  secpIdentityVerifier,
} from "../../src/index.ts";
import { runSuite, TEST_PUBLIC_KEY, FaultTransport } from "../runner/suite.mjs";
const byId = (id) => document.getElementById(id);
const status = byId("status"),
  rows = byId("results");
const params = new URLSearchParams(location.search);
const vid = params.has("vid") ? Number(params.get("vid")) : null;
const pid = params.has("pid") ? Number(params.get("pid")) : null;
let faultTransport;
let lastReport = null,
  running = false,
  selected = null,
  generation = 0;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const matches = (port) => {
  const i = port.getInfo();
  return (
    (vid === null || i.usbVendorId === vid) &&
    (pid === null || i.usbProductId === pid)
  );
};
const portLabel = (port) => {
  const i = port.getInfo();
  return [i.usbVendorId, i.usbProductId]
    .map((x) => (x === undefined ? "unknown" : x.toString(16).padStart(4, "0")))
    .join(":");
};
async function choose() {
  if (!("serial" in navigator))
    throw Error("此浏览器没有 Web Serial，请使用完整 Edge/Chromium。");
  const ports = (await navigator.serial.getPorts()).filter(matches);
  if (ports.length !== 1)
    throw Error(
      ports.length
        ? "匹配到多个设备，请指定 VID/PID 并只连接一台测试设备。"
        : "没有已授权设备。自动运行请先配置串口预授权；交互运行可点击“授权设备”。",
    );
  selected = ports[0];
  return selected;
}
const connector = {
  hardware: true,
  label: "browser Web Serial → ESP32 USB-UART / NVS",
  async connect(options = {}) {
    const port = selected ?? (await choose());
    status.textContent = `连接 ${portLabel(port)}，正在建立加密会话…`;
    const transport = await WebSerialTransport.open(port);
    try {
      return await connectHost(
        (faultTransport = new FaultTransport(transport)),
        {
          walletGeneration: 1,
          backendGeneration: 1,
          hostRunGeneration: ++generation,
        },
        options.expectedPublicKey ?? TEST_PUBLIC_KEY,
        secpIdentityVerifier,
        async (code) => {
          byId("pairing").textContent = code;
          return options.approvePairing !== false;
        },
      );
    } catch (e) {
      selected = null;
      throw e;
    }
  },
  corruptNextRequest() {
    faultTransport.corruptNextRequest();
  },
  async reconnect() {
    selected = null;
    status.textContent = "设备重启中，等待串口恢复…"; // 重启并不一定引发 USB 枚举事件，USB-UART 桥接芯片通常仍在线。
    await sleep(1800);
    for (let i = 0; i < 100; i++) {
      try {
        await choose();
        return;
      } catch {
        await sleep(100);
      }
    }
    throw Error("重启后没有找到唯一的已授权测试设备。");
  },
  async close() {
    selected = null;
  },
};
function row(result) {
  const tr = document.createElement("tr");
  for (const text of [
    result.id,
    result.name,
    result.status === "passed" ? "通过" : "失败",
    `${result.durationMs} ms`,
    result.error ?? "",
  ]) {
    const td = document.createElement("td");
    td.textContent = text;
    tr.append(td);
  }
  tr.dataset.status = result.status;
  rows.append(tr);
}
async function run() {
  if (running) throw Error("测试正在执行。");
  running = true;
  lastReport = null;
  rows.replaceChildren();
  byId("run").disabled = true;
  byId("authorize").disabled = true;
  status.textContent = "准备测试…";
  try {
    lastReport = await runSuite(connector, row);
    status.textContent = `完成：${lastReport.results.length} 项通过。`;
  } catch (e) {
    lastReport = {
      status: "failed",
      hardware: true,
      transport: connector.label,
      error: e.message,
      results: e.results ?? [],
    };
    status.textContent = `失败：${e.message}`;
  } finally {
    running = false;
    byId("run").disabled = false;
    byId("authorize").disabled = false;
    byId("report").disabled = false;
  }
  return lastReport;
}
byId("run").addEventListener("click", run);
byId("authorize").addEventListener("click", async () => {
  try {
    const filters =
      vid === null
        ? []
        : [
            {
              usbVendorId: vid,
              ...(pid === null ? {} : { usbProductId: pid }),
            },
          ];
    selected = await navigator.serial.requestPort({ filters });
    status.textContent = `已授权 ${portLabel(selected)}。`;
  } catch (e) {
    status.textContent = `授权未完成：${e.message}`;
  }
});
byId("report").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {
      type: "application/json",
    }),
    url = URL.createObjectURL(blob),
    a = document.createElement("a");
  a.href = url;
  a.download = "vaultlink-hardware-e2e.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
// 自动化通过这个窄入口运行相同页面，不替换 navigator.serial 或 SDK。
window.vlpE2E = {
  run,
  get report() {
    return lastReport;
  },
  get running() {
    return running;
  },
};
status.textContent =
  "准备就绪；自动模式使用预授权设备，所有授权决定来自 E2E 固件测试脚本。";
