import { spawn } from "node:child_process";
import { mkdtemp, writeFile, readFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import {
  connectHost,
  secpIdentityVerifier,
  PaymentPolicy,
} from "../../dist/index.js";
import { AtomicFilePolicyStore } from "../../src/node-store.mjs";
const root = fileURLToPath(new URL("../../", import.meta.url));
await build({
  entryPoints: [path.join(root, "integration/runner/suite.mjs")],
  outfile: path.join(root, "integration/artifacts/suite-node.mjs"),
  platform: "node",
  format: "esm",
  bundle: true,
});
const { runSuite, TEST_PUBLIC_KEY, FaultTransport } = await import(
  "../artifacts/suite-node.mjs"
);
const dir = await mkdtemp(path.join(tmpdir(), "vlp-native-e2e-"));
let child, exit, reader, faultTransport;
const connector = {
  hardware: false,
  label: "native C++ process / real pipes / atomic file storage",
  async connect(options = {}) {
    if (!child || child.exitCode !== null) {
      child = spawn(
        path.join(root, "integration/artifacts/native-device"),
        [dir],
        { stdio: ["pipe", "pipe", "inherit"] },
      );
      exit = new Promise((resolve, reject) => {
        child.once("exit", resolve);
        child.once("error", reject);
      });
      child.stdin.on("error", () => {}); // 写入回调/EOF 将错误传给真实客户端，避免 EventEmitter 二次未处理错误。
      reader = child.stdout[Symbol.asyncIterator]();
    }
    const instance = child;
    const transport = {
      async read() {
        const v = await reader.next();
        return v.done ? null : new Uint8Array(v.value);
      },
      async write(bytes) {
        await new Promise((resolve, reject) =>
          instance.stdin.write(bytes, (e) => (e ? reject(e) : resolve())),
        );
      },
      async close() {
        instance.stdin.end();
      },
    };
    return connectHost(
      (faultTransport = new FaultTransport(transport)),
      {
        walletGeneration: 1,
        backendGeneration: 1,
        hostRunGeneration: crypto.getRandomValues(new Uint32Array(1))[0] || 1,
      },
      options.expectedPublicKey ?? TEST_PUBLIC_KEY,
      secpIdentityVerifier,
      async () => options.approvePairing !== false,
    );
  },
  corruptNextRequest() {
    faultTransport.corruptNextRequest();
  },
  async reconnect(expectedRestart = true) {
    if (child?.exitCode === null) {
      await waitForExit(15000);
    }
    assertExit(expectedRestart);
    child = undefined;
  },
  async close() {
    if (child?.exitCode === null) {
      child.stdin.end();
      try {
        await waitForExit(1000);
      } catch {
        child.kill();
        await exit;
      }
    }
  },
};
async function waitForExit(ms) {
  let timer;
  try {
    await Promise.race([
      exit,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error("native exit timeout")), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
function assertExit(expectedRestart) {
  if (child && child.exitCode !== (expectedRestart ? 75 : 0))
    throw Error(`expected controlled restart 75, got ${child.exitCode}`);
}
let report;
try {
  report = await runSuite(connector, async (row) => {
    if (row.id === "E2E-02" && row.status === "passed") {
      // 复制真实 C++ 已提交文件后交给 TS 恢复，不让两个执行权威写同一账本。
      const copy = path.join(dir, "ts-crosscheck");
      await writeFile(copy, await readFile(path.join(dir, "policy")));
      const restored = await PaymentPolicy.open(
        new AtomicFilePolicyStore(copy),
        Buffer.from(TEST_PUBLIC_KEY).toString("hex"),
      );
      const state = await restored.snapshot();
      if (
        state.sessions[0].used !== 300n ||
        state.sessions[0].active !== false ||
        state.pending[0].state !== "signed"
      )
        throw Error("C++ → TypeScript persistent state crosscheck failed");
    }
    console.log(
      `${row.status} ${row.id} ${row.name}${row.error ? " — " + row.error : ""}`,
    );
  });
} catch (e) {
  report = {
    status: "failed",
    hardware: false,
    error: e.message,
    results: e.results ?? [],
  };
  process.exitCode = 1;
} finally {
  await connector.close();
  await rm(dir, { recursive: true, force: true });
}
await mkdir(path.join(root, "integration/artifacts"), { recursive: true });
await writeFile(
  path.join(root, "integration/artifacts/native-report.json"),
  JSON.stringify(report, null, 2) + "\n",
);
