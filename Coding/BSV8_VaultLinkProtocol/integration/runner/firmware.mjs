import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import "./verify-vendor.mjs";
const root = fileURLToPath(new URL("../../", import.meta.url));
const python = path.join(
  root,
  ".tools/venv",
  process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
);
const result = spawnSync(
  python,
  ["-m", "platformio", "run", "-d", "integration/esp32"],
  { cwd: root, stdio: "inherit" },
);
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
