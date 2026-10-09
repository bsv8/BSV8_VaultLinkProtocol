import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = fileURLToPath(new URL("../../", import.meta.url)),
  windows = process.platform === "win32";
function run(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: root, stdio: "inherit" });
  if (r.error) throw r.error;
  if (r.status !== 0) process.exit(r.status ?? 1);
}
run(process.env.VLP_PYTHON ?? (windows ? "python" : "python3"), [
  "-m",
  "venv",
  ".tools/venv",
]);
const python = path.join(
  root,
  ".tools/venv",
  windows ? "Scripts/python.exe" : "bin/python",
);
run(python, [
  "-m",
  "pip",
  "install",
  "-r",
  "integration/runner/requirements.txt",
]);
console.log(
  "ESP32 构建/上传工具已准备。浏览器使用完整 Edge；自动测试在独立资料目录预授权选定设备。",
);
