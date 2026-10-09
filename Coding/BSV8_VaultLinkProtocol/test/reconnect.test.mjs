import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DeviceIdentityKey, PaymentPolicy, unhex } from "../dist/index.js";
import { AtomicFilePolicyStore } from "../src/node-store.mjs";

test("unpowered-device restart: same identity/config, locked old key, no old session or payment replay", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "vlp-reconnect-"));
  const privateKey = unhex(
    "0000000000000000000000000000000000000000000000000000000000000001",
  );
  const first = new DeviceIdentityKey(privateKey);
  const publicKey = Buffer.from(first.publicKey()).toString("hex");
  const store = new AtomicFilePolicyStore(path.join(dir, "policy.cbor"));
  const config = {
    id: "channel",
    owner: "app",
    kind: "app",
    network: "main",
    paymentType: "p2pkh",
    enabled: true,
    singleLimit: 10n,
    defaultSessionLimit: 20n,
    revision: 1,
  };
  const payment = {
    requestId: "payment-one",
    channelId: "channel",
    owner: "app",
    kind: "app",
    sessionId: "connection-one",
    network: "main",
    paymentType: "p2pkh",
    amount: 7n,
    commitment: new Uint8Array(32).fill(3),
  };
  try {
    const old = await PaymentPolicy.open(store, publicKey);
    await old.configure(config, true);
    await old.startSession("connection-one", "app", true);
    // 已落盘预占，结果尚未交付时断电：重启不推断为未签名。
    await old.reserve(payment);
    old.lock();
    first.close();
    assert.throws(() => first.publicKey(), /locked/);
    await assert.rejects(old.quote(payment), /unavailable/);
    const recovered = await PaymentPolicy.open(
      new AtomicFilePolicyStore(path.join(dir, "policy.cbor")),
      publicKey,
    );
    const snapshot = await recovered.snapshot();
    assert.deepEqual(snapshot.channels, [config]);
    assert.equal(snapshot.sessions[0].active, false);
    assert.equal(snapshot.sessions[0].used, 7n);
    assert.equal(snapshot.pending[0].state, "unknown");
    await assert.rejects(
      recovered.assertExecutable("payment-one"),
      /invalid-state/,
    );
    await assert.rejects(
      recovered.quote({ ...payment, requestId: "payment-two" }),
      /session/,
    );
    await assert.rejects(
      recovered.startSession("connection-two", "app", false),
      /confirmation/,
    );
    await recovered.startSession("connection-two", "app", true);
    await assert.rejects(
      recovered.reserve({ ...payment, sessionId: "connection-two" }),
      /reuse/,
    );
    // PIN/Flash 实现属于固件；这里仅验证重新解锁后装载同一 Key 的协议身份。
    const unlocked = new DeviceIdentityKey(privateKey);
    assert.equal(Buffer.from(unlocked.publicKey()).toString("hex"), publicKey);
    unlocked.close();
  } finally {
    first.close();
    privateKey.fill(0);
    await rm(dir, { recursive: true, force: true });
  }
});
