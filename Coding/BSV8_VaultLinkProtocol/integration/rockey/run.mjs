import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  readFileSync,
  mkdirSync,
  chmodSync,
  writeFileSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir, homedir } from "node:os";
import path from "node:path";
const root = fileURLToPath(new URL("../../", import.meta.url));
const rockey =
  process.env.VLP_ROCKEY_ROOT ?? path.resolve(root, "../../../Rockey");
const python =
  process.env.ROCKEY_PYTHON ?? path.join(root, ".tools/venv/bin/python");
const args = new Set(process.argv.slice(2));
const allowed = new Set([
  "--prepare",
  "--list",
  "--flash",
  "--initialize-empty-test-device",
]);
for (const arg of args)
  if (!allowed.has(arg)) throw Error("unknown argument: " + arg);
if (
  ["--prepare", "--list", "--flash"].filter((arg) => args.has(arg)).length > 1
)
  throw Error("choose one mode");
if (args.has("--initialize-empty-test-device") && !args.has("--flash"))
  throw Error("first storage initialization requires --flash");
const env = process.env.ROCKEY_E2E_ENV ?? "m5stack-core-e2e-en";
if (!["m5stack-core-e2e-en", "m5stack-core-e2e-zh-hans"].includes(env))
  throw Error("only isolated product E2E environments are permitted");
function run(command, argv, options = {}) {
  const p = spawnSync(command, argv, {
    cwd: root,
    stdio: "inherit",
    ...options,
  });
  if (p.error) throw p.error;
  if (p.status !== 0) throw Error(command + " failed with exit " + p.status);
  return p;
}
const pio = (argv) =>
  run(python, ["-m", "platformio", ...argv], { cwd: rockey });
const buildRecord = path.join(
  rockey,
  ".pio/build",
  env,
  "rockey-e2e-build.json",
);
function buildProduct() {
  process.env.ROCKEY_BUILD_ID =
    "rockey-e2e-" + new Date().toISOString().replace(/[^0-9TZ]/g, "");
  pio(["run", "-e", env]);
  const firmware = readFileSync(
    path.join(rockey, ".pio/build", env, "firmware.bin"),
  );
  writeFileSync(
    buildRecord,
    JSON.stringify(
      {
        buildId: process.env.ROCKEY_BUILD_ID,
        sha256: createHash("sha256").update(firmware).digest("hex"),
      },
      null,
      2,
    ) + "\n",
  );
}
if (args.has("--prepare")) {
  run(process.execPath, ["--test", "integration/rockey/wire.test.mjs"]);
  run(process.execPath, ["integration/rockey/server.mjs", "--check"]);
  buildProduct();
  console.log(
    "Prepared real product test firmware; no device opened or flashed.",
  );
  process.exit(0);
}
const query = run(
  python,
  [
    "-c",
    "import json; from serial.tools.list_ports import comports; print(json.dumps([dict(port=p.device,vid=p.vid,pid=p.pid,description=p.description,serialNumber=p.serial_number) for p in comports() if p.vid is not None]))",
  ],
  { stdio: "pipe", encoding: "utf8" },
);
const ports = JSON.parse(query.stdout);
if (args.has("--list")) {
  console.log(JSON.stringify(ports, null, 2));
  process.exit(0);
}
// VID/PID 是串口桥身份，不能证明是 RocKey。必须由操作人指定物理端口。
if (!process.env.VLP_SERIAL_PORT)
  throw Error(
    "Specify VLP_SERIAL_PORT after confirming the connected RocKey; USB bridge VID/PID alone is insufficient.",
  );
const selected = ports.filter((p) => p.port === process.env.VLP_SERIAL_PORT);
if (selected.length !== 1)
  throw Error("Selected physical hardware absent; no test was marked passed.");
const device = selected[0];
console.log("Selected physical port: " + device.port);
if (
  ports.filter((p) => p.vid === device.vid && p.pid === device.pid).length !== 1
)
  throw Error(
    "Multiple identical USB bridges: leave only the intended RocKey connected.",
  );
const core =
  process.env.PLATFORMIO_CORE_DIR ?? path.join(homedir(), ".platformio");
const esptool = path.join(core, "packages/tool-esptoolpy/esptool.py");
const esptoolRun = (argv) =>
  run(python, [
    esptool,
    "--chip",
    "esp32",
    "--port",
    device.port,
    "--baud",
    "115200",
    ...argv,
  ]);
if (args.has("--flash")) {
  buildProduct();
  const identity = run(
    python,
    [esptool, "--chip", "esp32", "--port", device.port, "flash_id"],
    { stdio: "pipe", encoding: "utf8" },
  );
  console.log(identity.stdout);
  if (!/Detected flash size: 4MB/.test(identity.stdout))
    throw Error("unexpected Flash size; no upload performed");
  // 保存完整 Flash（含现有密钥封装），不打印内容、不写进测试报告或仓库。
  const backupDir = path.join(
    process.env.ROCKEY_BACKUP_DIR ??
      path.join(homedir(), ".codex/private/rockey-backups"),
    new Date().toISOString().replaceAll(":", "-"),
  );
  mkdirSync(backupDir, { recursive: true, mode: 0o700 });
  chmodSync(backupDir, 0o700);
  const backup = path.join(backupDir, "before-e2e-flash.bin");
  esptoolRun(["read_flash", "0", "0x400000", backup]);
  chmodSync(backup, 0o600);
  const bytes = readFileSync(backup);
  if (bytes.length !== 0x400000)
    throw Error("incomplete flash backup; upload refused");
  const partitions = readFileSync(
    path.join(rockey, ".pio/build", env, "partitions.bin"),
  );
  const current = bytes.subarray(0x8000, 0x8000 + partitions.length);
  if (
    !current.equals(partitions) &&
    !args.has("--initialize-empty-test-device")
  )
    throw Error(
      "Partition layout differs. Backup saved; upload refused. Only an explicitly empty dedicated test device may use --initialize-empty-test-device.",
    );
  writeFileSync(
    path.join(backupDir, "metadata.json"),
    JSON.stringify(
      {
        port: device.port,
        timestamp: new Date().toISOString(),
        bytes: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        target: env,
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  console.log("Private pre-flash backup saved: " + backup);
  pio(["run", "-e", env, "-t", "upload", "--upload-port", device.port]);
  if (args.has("--initialize-empty-test-device")) {
    // 明确空测试设备的首次建盘，和日后只更新固件是两个不同动作。
    // 禁止整片擦除；仅初始化已备份的 LittleFS 区域。
    const dir = mkdtempSync(path.join(tmpdir(), "rockey-empty-fs-"));
    try {
      const input = path.join(dir, "empty");
      mkdirSync(input);
      const image = path.join(dir, "littlefs.bin");
      run(path.join(core, "packages/tool-mklittlefs/mklittlefs"), [
        "-c",
        input,
        "-b",
        "4096",
        "-p",
        "256",
        "-s",
        String(0xb0000),
        image,
      ]);
      esptoolRun(["write_flash", "0x350000", image]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  // 完整备份 SHA 及设备秘密只留在私有备份目录，不进入可分享报告。
}
if (args.has("--initialize-empty-test-device") && !args.has("--flash"))
  throw Error("first storage initialization requires --flash");
const record = JSON.parse(readFileSync(buildRecord, "utf8"));
const firmware = readFileSync(
  path.join(rockey, ".pio/build", env, "firmware.bin"),
);
if (createHash("sha256").update(firmware).digest("hex") !== record.sha256)
  throw Error("test firmware changed after preparation; rerun prepare/flash");
const runtimeEnv = {
  ...process.env,
  VLP_USB_VID: String(device.vid),
  VLP_USB_PID: String(device.pid),
  VLP_SELECTED_SERIAL_PORT: device.port,
  ROCKEY_E2E_EXPECTED_BUILD_ID: record.buildId,
  ROCKEY_E2E_FIRMWARE_SHA256: createHash("sha256")
    .update(firmware)
    .digest("hex"),
};

run(
  process.execPath,
  [
    path.join(root, "node_modules/@playwright/test/cli.js"),
    "test",
    "-c",
    "integration/rockey/playwright.config.mjs",
    "hardware.spec.mjs",
  ],
  { env: runtimeEnv },
);
