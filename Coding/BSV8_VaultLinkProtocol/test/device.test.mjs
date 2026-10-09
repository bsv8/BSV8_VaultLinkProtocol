import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { frame, Type } from "../dist/index.js";
test("portable C++ core compiles with warnings as errors and consumes TypeScript wire bytes", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "vlp-device-"));
  try {
    const binary = path.join(dir, "core"),
      fixture = path.join(dir, "frame");
    const cc = spawnSync(
      "c++",
      [
        "-std=c++17",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fsanitize=address,undefined",
        "device/core_test.cpp",
        "-o",
        binary,
      ],
      { encoding: "utf8" },
    );
    assert.equal(cc.status, 0, cc.stderr);
    await writeFile(
      fixture,
      frame({ type: Type.REQUEST, seq: 7, payload: new Uint8Array(1024) }),
    );
    const run = spawnSync(binary, [fixture], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /passed/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
