import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = fileURLToPath(new URL("../../", import.meta.url));
const python = path.join(
  root,
  ".tools/venv",
  process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
);
function run(cmd, args, options = {}) {
  const p = spawnSync(cmd, args, { cwd: root, stdio: "inherit", ...options });
  if (p.error) throw p.error;
  if (p.status !== 0) throw Error(`${cmd} exited ${p.status}`);
  return p;
}
const query = spawnSync(
  python,
  [
    "-c",
    "import json; from serial.tools.list_ports import comports; print(json.dumps([dict(port=p.device,vid=p.vid,pid=p.pid) for p in comports() if p.vid is not None]))",
  ],
  { cwd: root, encoding: "utf8" },
);
if (query.error || query.status !== 0)
  throw Error("串口工具不可用，请先运行 npm run integration:prepare。");
const ids = ["VLP_USB_VID", "VLP_USB_PID"].map((k) =>
  process.env[k] === undefined ? null : Number(process.env[k]),
);
if (ids.some((n) => n !== null && (!Number.isInteger(n) || n < 0 || n > 65535)))
  throw Error("VID/PID 必须为合法 16 位整数。");
const ports = JSON.parse(query.stdout).filter(
  (p) =>
    (ids[0] === null || p.vid === ids[0]) &&
    (ids[1] === null || p.pid === ids[1]) &&
    (!process.env.VLP_SERIAL_PORT || p.port === process.env.VLP_SERIAL_PORT),
);
if (ports.length !== 1)
  throw Error(
    ports.length
      ? "匹配到多个 USB 串口，请使用 VLP_SERIAL_PORT/VID/PID 指定。"
      : "尚未找到测试硬件；不会把无设备记为通过。",
  );
const device = ports[0];
process.env.VLP_USB_VID = String(device.vid);
process.env.VLP_USB_PID = String(device.pid);
process.env.VLP_SELECTED_SERIAL_PORT = device.port;
console.log(
  `真实测试设备：${device.port} VID=0x${device.vid.toString(16)} PID=0x${device.pid.toString(16)}`,
);
if (process.argv.includes("--flash")) {
  run(python, [
    "-m",
    "platformio",
    "run",
    "-d",
    "integration/esp32",
    "-e",
    process.env.VLP_BOARD ?? "m5stack-e2e",
    "-t",
    "upload",
    "--upload-port",
    device.port,
  ]);
}
const playwright = path.join(root, "node_modules/@playwright/test/cli.js");
run(process.execPath, [
  playwright,
  "test",
  "-c",
  "integration/runner/playwright.config.mjs",
  "hardware.spec.mjs",
]);
