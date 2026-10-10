import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  feePoolScript,
  inspectFeePool,
  serializeTransaction,
  p2pkhScript,
  sha256d,
  hex,
  DeviceIdentityKey,
  PaymentPolicy,
} from "../dist/index.js";
const secret = new Uint8Array(32);
secret[31] = 1;
const pub = secp256k1.getPublicKey(secret, true),
  seller = secp256k1.getPublicKey(2n, true),
  arbiter = secp256k1.getPublicKey(3n, true);
async function fixture(family) {
  const keys = family === "connect" ? [seller, pub] : [pub, seller, arbiter];
  const prior = serializeTransaction({
    version: 1,
    inputs: [
      {
        txid: new Uint8Array(32),
        vout: 0xffffffff,
        script: Uint8Array.of(1),
        sequence: 0xffffffff,
      },
    ],
    outputs: [{ satoshis: 2000n, script: p2pkhScript(pub) }],
    locktime: 0,
  });
  const fund = {
    version: 1,
    inputs: [
      {
        txid: await sha256d(prior),
        vout: 0,
        script: new Uint8Array(),
        sequence: 0xfffffffe,
      },
    ],
    outputs: [
      { satoshis: 1000n, script: feePoolScript(keys) },
      { satoshis: 990n, script: p2pkhScript(pub) },
    ],
    locktime: 0,
  };
  const funding = serializeTransaction(fund);
  const state = {
    version: 1,
    inputs: [
      {
        txid: await sha256d(funding),
        vout: 0,
        script: new Uint8Array(),
        sequence: 0xfffffffe,
      },
    ],
    outputs: keys.map((k) => ({
      satoshis: hex(k) === hex(pub) ? 890n : hex(k) === hex(seller) ? 100n : 0n,
      script: p2pkhScript(k),
    })),
    locktime: 0,
  };
  return { prior, fund, funding, state };
}
for (const family of ["connect", "bitfs"])
  test(`${family}: actual script roles, funding evidence, cumulative outputs, all-ForkID signatures and altered evidence rejection`, async () => {
    const f = await fixture(family),
      raw = serializeTransaction(f.state);
    const fund = await inspectFeePool(
      f.funding,
      [f.prior],
      pub,
      family,
      "fund",
    );
    assert.equal(fund.locked, 1000n);
    assert.equal(fund.paid, 0n);
    assert.equal(fund.fee, 10n);
    const state = await inspectFeePool(raw, [f.funding], pub, family, "state");
    assert.equal(state.paid, 100n);
    assert.equal(state.fee, 10n);
    assert.equal(state.change, 890n);
    const key = new DeviceIdentityKey(secret);
    const sigs = await key.signAllFeePool(
      raw,
      [f.funding],
      family,
      "state",
      new AbortController().signal,
      async () => {},
    );
    assert.equal(sigs[0].at(-1), 0x41);
    assert.equal(
      secp256k1.verify(sigs[0].slice(0, -1), state.digests[0], pub, {
        prehash: false,
        lowS: true,
      }),
      true,
    );
    const altered = structuredClone(f.state);
    altered.outputs[0].script = p2pkhScript(secp256k1.getPublicKey(4n, true));
    await assert.rejects(
      inspectFeePool(
        serializeTransaction(altered),
        [f.funding],
        pub,
        family,
        "state",
      ),
      /invalid-pool-output/,
    );
    const bad = f.funding.slice();
    bad[5] ^= 1;
    await assert.rejects(
      inspectFeePool(raw, [bad], pub, family, "state"),
      /invalid-prevout/,
    );
    await assert.rejects(
      inspectFeePool(raw, [f.funding], seller, family, "state"),
      /wrong-key/,
    );
    if (family === "bitfs") {
      const proof = structuredClone(f.state);
      proof.outputs.push({
        satoshis: 0n,
        script: Uint8Array.of(0, 0x6a, 1, 7),
      });
      assert.equal(
        (
          await inspectFeePool(
            serializeTransaction(proof),
            [f.funding],
            pub,
            family,
            "state",
          )
        ).paid,
        100n,
      );
      proof.outputs[3].satoshis = 1n;
      await assert.rejects(
        inspectFeePool(
          serializeTransaction(proof),
          [f.funding],
          pub,
          family,
          "state",
        ),
        /invalid-payment-proof/,
      );
    }
    key.close();
    await assert.rejects(
      key.signAllFeePool(
        raw,
        [f.funding],
        family,
        "state",
        new AbortController().signal,
        async () => {},
      ),
      /locked/,
    );
  });
test("actual disk pool ledger counts deltas across channels/restart, closes at zero, rejects concurrent/stale/rollback and restores proven-unexecuted reservation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vlp-pool-")),
    file = join(dir, "policy.json");
  const store = {
    async load() {
      try {
        return JSON.parse(await readFile(file, "utf8"), (_k, v) =>
          v && v.bigint
            ? BigInt(v.bigint)
            : v && v.bytes
              ? Uint8Array.from(v.bytes)
              : v,
        );
      } catch (e) {
        if (e.code === "ENOENT") return null;
        throw e;
      }
    },
    async save(state) {
      await writeFile(
        file + ".tmp",
        JSON.stringify(state, (_k, v) =>
          typeof v === "bigint"
            ? { bigint: String(v) }
            : v instanceof Uint8Array
              ? { bytes: Array.from(v) }
              : v,
        ),
      );
      await rename(file + ".tmp", file);
    },
  };
  try {
    let p = await PaymentPolicy.open(store, hex(pub));
    for (const id of ["a", "b"])
      await p.configure(
        {
          id,
          owner: "app",
          kind: "app",
          network: "main",
          paymentType: "feepool.connect",
          enabled: true,
          singleLimit: 100n,
          defaultSessionLimit: 150n,
          revision: 1,
        },
        true,
      );
    await p.startSession("connection", "app", true);
    const binding = await sha256d(feePoolScript([seller, pub]));
    const payment = async (
      id,
      paid,
      channelId = "a",
      sessionId = "connection",
    ) => ({
      requestId: id,
      channelId,
      owner: "app",
      kind: "app",
      network: "main",
      paymentType: "feepool.connect",
      sessionId,
      commitment: new Uint8Array(32).fill(1),
      ...(await p.inspectPool("pool", binding, paid)),
    });
    const one = await payment("one", 100n);
    await p.reserve(one);
    await assert.rejects(p.quote(await payment("concurrent", 110n)), /busy/);
    await p.markSigned("one");
    const two = await payment("two", 150n, "b");
    assert.equal(two.amount, 50n);
    await p.reserve(two);
    await p.markSigned("two");
    const close = await payment("close", 150n);
    assert.equal(close.amount, 0n);
    await p.reserve(close);
    await p.markSigned("close");
    const cancelled = await payment("cancelled", 151n);
    const q = await p.quote(cancelled);
    assert.deepEqual(q.reasons, ["session-limit"]);
    await p.reserve(cancelled, {
      requestCommitment: cancelled.commitment,
      configRevision: q.configRevision,
      sessionRevision: q.sessionRevision,
    });
    await p.releaseUnexecuted("cancelled");
    assert.equal((await p.inspectPool("pool", binding, 151n)).amount, 1n);
    await assert.rejects(
      p.inspectPool("pool", binding, 149n),
      /payment-rollback/,
    );
    p.lock();
    p = await PaymentPolicy.open(store, hex(pub));
    await p.startSession("next-connection", "app", true);
    assert.equal((await p.inspectPool("pool", binding, 160n)).amount, 10n);
    const unknown = await payment("unknown", 160n, "a", "next-connection");
    await p.reserve(unknown);
    p.lock();
    p = await PaymentPolicy.open(store, hex(pub));
    assert.equal((await p.inspectPool("pool", binding, 160n)).amount, 0n);
    assert.equal(
      (await p.snapshot()).pending.find((p) => p.id === "unknown").state,
      "unknown",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
