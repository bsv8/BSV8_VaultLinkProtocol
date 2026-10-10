import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { build } from "esbuild";
const keymaster =
  process.env.VLP_KEYMASTER_ROOT ??
  fileURLToPath(new URL("../../../../../keymaster.cc/", import.meta.url));
const options = {
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  write: false,
  alias: {
    "@vaultlink/sdk": fileURLToPath(
      new URL("../../src/index.ts", import.meta.url),
    ),
  },
};
const bundles = await Promise.all([
  build({
    ...options,
    entryPoints: [fileURLToPath(new URL("./main.mjs", import.meta.url))],
    alias: {
      ...options.alias,
      "keymaster-rockey-e2e-client": path.join(
        keymaster,
        "Coding/keymaster/e2e-rockey/client.mjs",
      ),
    },
  }),
  build({
    ...options,
    entryPoints: [
      path.join(keymaster, "Coding/keymaster/e2e-rockey/worker.ts"),
    ],
  }),
]);
if (process.argv.includes("--check")) {
  console.log("Product E2E Window and real Keymaster Worker bundles compile.");
  process.exit(0);
}
const html =
  '<!doctype html><meta charset="utf-8"><title>RocKey Product E2E</title><h1>RocKey 产品固件 E2E</h1><p>真实 USB、Keymaster Worker 和设备 UI；只使用隔离测试钱包，不广播交易。</p><button id="authorize">授权 USB 设备</button> <button id="run">运行 E2E</button><p id="status">等待设备</p><ol id="results"></ol><script type="module" src="/main.js"></script>';
createServer((req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Permissions-Policy", "serial=(self)");
  if (req.url === "/main.js" || req.url === "/keymaster-worker.js") {
    res.setHeader("Content-Type", "text/javascript");
    res.end(bundles[req.url === "/main.js" ? 0 : 1].outputFiles[0].contents);
  } else if (new URL(req.url, "http://localhost").pathname === "/") {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(html);
  } else {
    res.statusCode = 404;
    res.end();
  }
}).listen(4175, "127.0.0.1", () =>
  console.log("RocKey product E2E http://127.0.0.1:4175"),
);
