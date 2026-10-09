import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  DeviceIdentityKey,
  PaymentPolicy,
  P2pkhPaymentOperation,
  serializeTransaction,
  p2pkhScript,
  sha256d,
  unhex,
} from "../dist/index.js";
import { AtomicFilePolicyStore } from "../src/node-store.mjs";
import { secp256k1 } from "@noble/curves/secp256k1";
const priv = unhex(
  "0000000000000000000000000000000000000000000000000000000000000001",
);
const config = {
  id: "channel",
  owner: "app",
  kind: "app",
  network: "main",
  paymentType: "p2pkh",
  enabled: true,
  singleLimit: 400n,
  defaultSessionLimit: 500n,
  revision: 1,
};
async function body(key, paymentId) {
  const previous = serializeTransaction({
    version: 1,
    inputs: [
      {
        txid: new Uint8Array(32),
        vout: 0xffffffff,
        script: Uint8Array.of(1),
        sequence: 0xffffffff,
      },
    ],
    outputs: [{ satoshis: 1000n, script: p2pkhScript(key.publicKey()) }],
    locktime: 0,
  });
  return {
    paymentId,
    channelId: "channel",
    prevTransactions: [previous],
    rawTx: serializeTransaction({
      version: 2,
      inputs: [
        {
          txid: await sha256d(previous),
          vout: 0,
          script: new Uint8Array(),
          sequence: 0xffffffff,
        },
      ],
      outputs: [
        {
          satoshis: 300n,
          script: p2pkhScript(secp256k1.getPublicKey(2n, true)),
        },
        { satoshis: 690n, script: p2pkhScript(key.publicKey()) },
      ],
      locktime: 0,
    }),
  };
}
test("real atomic file persistence with P2PKH output-based policy: auto then cumulative confirm", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "vlp-policy-"));
  const key = new DeviceIdentityKey(priv);
  try {
    const store = new AtomicFilePolicyStore(path.join(dir, "policy.cbor")),
      policy = await PaymentPolicy.open(
        store,
        Buffer.from(key.publicKey()).toString("hex"),
      );
    await policy.configure(config, true);
    await policy.startSession("session", "app", true);
    let prompts = 0;
    const op = new P2pkhPaymentOperation(
      key,
      policy,
      { owner: "app", kind: "app", sessionId: "session" },
      async (_p, q) => {
        prompts++;
        assert.deepEqual(q.reasons, ["session-limit"]);
        return { allow: true, raiseSessionLimit: 1000n };
      },
    );
    const signal = new AbortController().signal;
    for (const id of ["one", "two"]) {
      const core = await op.verify(await body(key, id));
      assert.equal(core.amount, 300n);
      assert.equal(await op.authorize(core, signal), true);
      const signed = await op.execute(core, signal);
      assert.equal(signed.signatures.length, 1);
    }
    assert.equal(prompts, 1);
    const snap = await policy.snapshot();
    assert.equal(snap.sessions[0].used, 600n);
    assert.equal(snap.sessions[0].limit, 1000n);
    assert.equal(snap.channels[0].defaultSessionLimit, 500n);
    const restored = await PaymentPolicy.open(
      store,
      Buffer.from(key.publicKey()).toString("hex"),
    );
    assert.equal((await restored.snapshot()).sessions[0].used, 600n);
    assert.equal((await restored.snapshot()).sessions[0].active, false);
  } finally {
    key.close();
    await rm(dir, { recursive: true, force: true });
  }
});
test("real persistence failure does not silently grant policy access", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "vlp-policy-"));
  try {
    const target = path.join(dir, "policy");
    const store = new AtomicFilePolicyStore(target),
      p = await PaymentPolicy.open(
        store,
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      );
    await mkdir(target);
    await assert.rejects(p.configure(config, true));
    await assert.rejects(p.snapshot(), /unavailable/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test("config revoked between reservation and signing is rejected and known-unexecuted quota released", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "vlp-policy-"));
  const key = new DeviceIdentityKey(priv);
  try {
    const p = await PaymentPolicy.open(
      new AtomicFilePolicyStore(path.join(dir, "policy")),
      Buffer.from(key.publicKey()).toString("hex"),
    );
    await p.configure(config, true);
    await p.startSession("session", "app", true);
    const op = new P2pkhPaymentOperation(
        key,
        p,
        { owner: "app", kind: "app", sessionId: "session" },
        async () => ({ allow: false }),
      ),
      core = await op.verify(await body(key, "revoked")),
      signal = new AbortController().signal;
    await op.authorize(core, signal);
    await p.configure({ ...config, enabled: false, revision: 2 }, true);
    await assert.rejects(op.execute(core, signal), /revoked/);
    assert.equal((await p.snapshot()).sessions[0].used, 0n);
  } finally {
    key.close();
    await rm(dir, { recursive: true, force: true });
  }
});
