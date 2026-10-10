import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

test("real C++ canonical encoder handles a 32KiB map within 40KiB extra heap", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vlp-cbor-memory-"));
  try {
    const exe = join(dir, "encoder");
    const compile = spawnSync(
      process.env.CXX ?? "c++",
      [
        "-std=c++17",
        "-O1",
        fileURLToPath(
          new URL("../device/cbor_memory_test.cpp", import.meta.url),
        ),
        "-o",
        exe,
      ],
      { encoding: "utf8" },
    );
    assert.equal(compile.status, 0, compile.stderr);
    const run = spawnSync(exe, [], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /PASS: canonical CBOR encoding/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
