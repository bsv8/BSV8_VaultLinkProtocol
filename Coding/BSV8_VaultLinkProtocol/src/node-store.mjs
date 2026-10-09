import { readFile, open, rename, mkdir, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { encode, decode } from "../dist/cbor.js";
/** 单执行权威使用；fsync 临时文件 -> rename -> fsync 目录。没有“失败也当成功”的内存 fallback。 */
export class AtomicFilePolicyStore {
  constructor(path) {
    this.path = path;
  }
  async load() {
    let raw;
    try {
      raw = await readFile(this.path);
    } catch (e) {
      if (e.code === "ENOENT") return null;
      throw e;
    }
    const s = decode(raw, 65536);
    if (
      !s ||
      typeof s !== "object" ||
      !Array.isArray(s.channels) ||
      !Array.isArray(s.sessions) ||
      !Array.isArray(s.pending)
    )
      throw Error("corrupt-state");
    for (const c of s.channels) {
      c.singleLimit = BigInt(c.singleLimit);
      c.defaultSessionLimit = BigInt(c.defaultSessionLimit);
    }
    for (const t of s.sessions) {
      t.limit = BigInt(t.limit);
      t.used = BigInt(t.used);
    }
    for (const t of s.pending) t.amount = BigInt(t.amount);
    return s;
  }
  async save(snapshot) {
    const bytes = encode(snapshot, 65536);
    await mkdir(dirname(this.path), { recursive: true });
    const temp = this.path + "." + crypto.randomUUID() + ".tmp";
    let file;
    try {
      file = await open(temp, "wx", 0o600);
      await file.writeFile(bytes);
      await file.sync();
      await file.close();
      file = undefined;
      await rename(temp, this.path);
      const dir = await open(dirname(this.path), "r");
      try {
        await dir.sync();
      } finally {
        await dir.close();
      }
    } finally {
      await file?.close();
      await unlink(temp).catch((e) => {
        if (e.code !== "ENOENT") throw e;
      });
    }
  }
}
