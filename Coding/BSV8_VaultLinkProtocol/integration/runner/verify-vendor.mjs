import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
const dir = new URL("../esp32/lib/mbedtls-extra/", import.meta.url);
const manifest = JSON.parse(
  await readFile(new URL("manifest.json", dir), "utf8"),
);
for (const entry of manifest) {
  const bytes = await readFile(new URL(entry.file, dir));
  if (createHash("sha256").update(bytes).digest("hex") !== entry.sha256)
    throw Error("Upstream file hash mismatch: " + entry.file);
}
console.log(
  "mbedTLS 2.28.7 extra modules: source hashes match upstream manifest",
);
