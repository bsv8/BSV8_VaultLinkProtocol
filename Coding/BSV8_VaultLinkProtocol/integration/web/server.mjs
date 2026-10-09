import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
const bundle = await build({
  entryPoints: [fileURLToPath(new URL("./main.mjs", import.meta.url))],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  write: false,
});
const html = await readFile(new URL("./index.html", import.meta.url));
const port = Number(process.env.VLP_E2E_PORT ?? 4173);
createServer((request, response) => {
  const pathname = new URL(request.url, "http://127.0.0.1").pathname;
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Permissions-Policy", "serial=(self)");
  if (pathname === "/") {
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.end(html);
  } else if (pathname === "/main.js") {
    response.setHeader("Content-Type", "text/javascript; charset=utf-8");
    response.end(bundle.outputFiles[0].contents);
  } else {
    response.writeHead(404);
    response.end("Not found");
  }
}).listen(port, "127.0.0.1", () =>
  console.log(`VaultLink E2E page http://127.0.0.1:${port}`),
);
