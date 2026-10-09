import { spawnSync } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = fileURLToPath(new URL("../../", import.meta.url));
const prefix = process.env.VLP_MBEDTLS_PREFIX ?? "/opt/homebrew/opt/mbedtls@3";
const output = path.join(root, "integration/artifacts/native-device");
await mkdir(path.dirname(output), { recursive: true });
const p = spawnSync(
  process.env.CXX ?? "c++",
  [
    "-std=c++17",
    "-O1",
    "-g",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-fsanitize=address,undefined",
    `-I${prefix}/include`,
    path.join(root, "integration/native/main.cpp"),
    `-L${prefix}/lib`,
    `-Wl,-rpath,${prefix}/lib`,
    "-lmbedtls",
    "-lmbedx509",
    "-lmbedcrypto",
    "-o",
    output,
  ],
  { stdio: "inherit" },
);
if (p.status !== 0) process.exit(p.status ?? 1);
console.log("Native SDK built; not an ESP32/USB verification.");
