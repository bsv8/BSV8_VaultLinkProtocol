import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// 编译真正 SDK 头文件；生产构建必须缺少测试控制注册接口。
const root = fileURLToPath(new URL("../../", import.meta.url));
const prefix = process.env.VLP_MBEDTLS_PREFIX ?? "/opt/homebrew/opt/mbedtls@3";
const dir = await mkdtemp(path.join(tmpdir(), "vlp-production-gate-"));
const source = path.join(dir, "gate.cpp");
function compile() {
  return spawnSync(
    process.env.CXX ?? "c++",
    [
      "-std=c++17",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-fsyntax-only",
      `-I${root}`,
      `-I${prefix}/include`,
      source,
    ],
    { encoding: "utf8" },
  );
}
try {
  await writeFile(
    source,
    '#include "device/sdk/endpoint.hpp"\nint main() {}\n',
  );
  const baseline = compile();
  if (baseline.error || baseline.status !== 0)
    throw Error(baseline.error?.message ?? baseline.stderr);
  await writeFile(
    source,
    '#include "device/sdk/endpoint.hpp"\nvoid probe(vaultlink::Endpoint &endpoint) { endpoint.set_test_control({}); }\n',
  );
  const denied = compile();
  if (
    denied.error ||
    denied.status === 0 ||
    !denied.stderr.includes("set_test_control")
  )
    throw Error("production test-control compile gate failed");
  console.log(
    "Production SDK builds; E2E test-control API is absent without VLP_E2E_TEST_ONLY.",
  );
} finally {
  await rm(dir, { recursive: true, force: true });
}
