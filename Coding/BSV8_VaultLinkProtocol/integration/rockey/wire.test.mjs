import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { frame, Reader } from "./wire.mjs";
test("JS ↔ actual RocKey C++ test frame: fragmentation, boot noise, CRC and maximum length", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "rockey-wire-"));
  const rockey =
    process.env.VLP_ROCKEY_ROOT ??
    fileURLToPath(new URL("../../../../../Rockey/", import.meta.url));
  try {
    const source = path.join(dir, "wire.cpp"),
      exe = path.join(dir, "wire");
    writeFileSync(
      source,
      `#include "Coding/Rockey/e2e/wire.hpp"\n#include <iostream>\nint main(){rockey::e2e::Reader r;unsigned x;while(std::cin>>std::hex>>x)r.feed(uint8_t(x),[](uint8_t k,uint32_t id,const rockey::e2e::Bytes& b){auto f=rockey::e2e::frame(k,id,b);for(auto v:f)std::cout<<std::hex<<unsigned(v)<<" ";std::cout<<"\\n";});}\n`,
    );
    const built = spawnSync(
      process.env.CXX ?? "c++",
      [
        "-std=c++17",
        "-Wall",
        "-Wextra",
        "-Werror",
        `-I${rockey}`,
        source,
        "-o",
        exe,
      ],
      { encoding: "utf8" },
    );
    assert.equal(built.status, 0, built.stderr);
    const valid = [
      frame(2, 1, Uint8Array.of(1)),
      frame(1, 0, new Uint8Array(4096).fill(17)),
      frame(3, 0xffffffff, Uint8Array.of(5, 9)),
    ];
    const corrupt = frame(2, 99, Uint8Array.of(3));
    corrupt[11] ^= 1;
    const oversized = frame(2, 100, Uint8Array.of(3));
    oversized[9] = 255;
    oversized[10] = 255;
    const input = Uint8Array.from([
      1,
      2,
      82,
      75,
      ...corrupt,
      ...oversized,
      ...valid.flatMap((x) => [...x]),
    ]);
    const native = spawnSync(exe, [], {
      input: [...input].map((x) => x.toString(16)).join(" "),
      encoding: "utf8",
    });
    assert.equal(native.status, 0, native.stderr);
    const nativeBytes = Uint8Array.from(
      native.stdout
        .trim()
        .split(/\s+/)
        .map((x) => parseInt(x, 16)),
    );
    assert.deepEqual(
      nativeBytes,
      Uint8Array.from(valid.flatMap((x) => [...x])),
    );
    const reader = new Reader(),
      got = [];
    for (let i = 0; i < input.length; i += 7)
      got.push(...reader.feed(input.slice(i, i + 7)));
    assert.deepEqual(
      got.map((x) => frame(x.kind, x.id, x.payload)),
      valid,
    );
    assert.ok(reader.dropped >= 2);
    assert.throws(() => frame(2, 1, new Uint8Array(4097)), /invalid/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
test("actual button algorithm retains debounce, release gate, long press and injection expiry", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "rockey-buttons-"));
  const rockey =
    process.env.VLP_ROCKEY_ROOT ??
    fileURLToPath(new URL("../../../../../Rockey/", import.meta.url));
  try {
    const source = path.join(dir, "buttons.cpp"),
      exe = path.join(dir, "buttons");
    // 平台输入固定为实体按钮松开；注入进入真实 Buttons::Poll，不替换任何授权逻辑。
    writeFileSync(
      source,
      `#include "board/buttons.h"
#include <cassert>
unsigned long millis(){return 0;} void pinMode(unsigned char,unsigned char){} int digitalRead(unsigned char){return 1;}
int main(){using namespace rockey;Buttons b;b.Init({});
assert(!b.DevSetLevel(static_cast<Btn>(3),true,0,100));
assert(!b.DevSetLevel(Btn::kB,true,0,29));assert(!b.DevSetLevel(Btn::kB,true,0,4001));
assert(b.DevSetLevel(Btn::kB,true,100,2000));b.Poll(100);assert(!b.IsDown(Btn::kB));b.Poll(130);assert(b.IsDown(Btn::kB));
assert(b.NextEvent(Btn::kB,130)==BtnEvent::kNone);assert(b.NextEvent(Btn::kB,680)==BtnEvent::kLongPress);
assert(b.NextEvent(Btn::kB,1080)==BtnEvent::kHoldRepeat);
b.ArmReleaseGate();assert(b.GateActive());assert(b.NextEvent(Btn::kB,1090)==BtnEvent::kNone);
b.Poll(2101);b.Poll(2130);b.ClearGateIfSatisfied();assert(!b.GateActive());assert(!b.IsDown(Btn::kB));
assert(b.NextEvent(Btn::kB,2130)==BtnEvent::kNone);
b.DevSetLevel(Btn::kA,true,2200,100);b.Poll(2200);b.Poll(2230);
b.Poll(2301);b.Poll(2330);assert(b.NextEvent(Btn::kA,2330)==BtnEvent::kShortPress);assert(b.NextEvent(Btn::kA,2331)==BtnEvent::kNone);
// millis 溢出时，释放期限仍按有符号差值判断。
b.DevSetLevel(Btn::kC,true,0xffffff00u,400);b.Poll(0xffffff00u);b.Poll(0xffffff20u);assert(b.IsDown(Btn::kC));
b.Poll(145);b.Poll(180);assert(!b.IsDown(Btn::kC));
}\n`,
    );
    const built = spawnSync(
      process.env.CXX ?? "c++",
      [
        "-std=c++17",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-DROCKEY_BUILD_RELEASE=0",
        "-DROCKEY_DEV_BUTTON_API=1",
        "-DROCKEY_DEV_TEST_KEY=1",
        "-DROCKEY_E2E_ISOLATED=1",
        `-I${rockey}/src`,
        `-I${rockey}/tests/host/stubs`,
        source,
        path.join(rockey, "src/board/buttons.cpp"),
        "-o",
        exe,
      ],
      { encoding: "utf8" },
    );
    assert.equal(built.status, 0, built.stderr);
    const ran = spawnSync(exe, [], { encoding: "utf8" });
    assert.equal(ran.status, 0, ran.stderr);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
