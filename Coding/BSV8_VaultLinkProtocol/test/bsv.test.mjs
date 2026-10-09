import test from "node:test";
import assert from "node:assert/strict";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  serializeTransaction,
  p2pkhScript,
  sha256d,
  inspectP2pkh,
  DeviceIdentityKey,
  unhex,
  equal,
} from "../dist/index.js";
const priv = unhex(
  "0000000000000000000000000000000000000000000000000000000000000001",
);
async function sample() {
  const pub = secp256k1.getPublicKey(priv, true),
    peer = secp256k1.getPublicKey(2n, true),
    prev = {
      version: 1,
      inputs: [
        {
          txid: new Uint8Array(32),
          vout: 0xffffffff,
          script: Uint8Array.of(1),
          sequence: 0xffffffff,
        },
      ],
      outputs: [{ satoshis: 1000n, script: p2pkhScript(pub) }],
      locktime: 0,
    };
  const prior = serializeTransaction(prev),
    tx = {
      version: 2,
      inputs: [
        {
          txid: await sha256d(prior),
          vout: 0,
          script: new Uint8Array(),
          sequence: 0x12345678,
        },
      ],
      outputs: [
        { satoshis: 300n, script: p2pkhScript(peer) },
        { satoshis: 690n, script: p2pkhScript(pub) },
      ],
      locktime: 4,
    };
  return { pub, prior, tx, raw: serializeTransaction(tx) };
}
test("P2PKH validates real previous transaction/outpoint, ownership, fee, output-only amount", async () => {
  const s = await sample(),
    review = await inspectP2pkh(s.raw, [{ transaction: s.prior }], s.pub, 0);
  assert.equal(review.fee, 10n);
  assert.equal(review.amount, 300n);
  assert.equal(review.change, 690n);
  const key = new DeviceIdentityKey(priv);
  const signed = await key.signP2pkh(
    s.raw,
    [{ transaction: s.prior }],
    0,
    async (r) => r.amount === 300n,
  );
  assert.equal(signed.signature.at(-1), 0x41);
  assert.ok(
    secp256k1.verify(signed.signature.slice(0, -1), review.digest, s.pub, {
      prehash: false,
      lowS: true,
    }),
  );
  key.close();
  await assert.rejects(
    key.signP2pkh(s.raw, [{ transaction: s.prior }], 0, async () => true),
    /locked/,
  );
});
test("altered previous evidence, wrong key, unknown script and denied authorization never sign", async () => {
  const s = await sample(),
    bad = s.prior.slice();
  bad[5] ^= 1;
  await assert.rejects(inspectP2pkh(s.raw, [{ transaction: bad }], s.pub, 0));
  await assert.rejects(
    inspectP2pkh(
      s.raw,
      [{ transaction: s.prior }],
      secp256k1.getPublicKey(2n, true),
      0,
    ),
    /wrong-key/,
  );
  const tx = structuredClone(s.tx);
  tx.outputs[0].script = Uint8Array.of(0x51);
  await assert.rejects(
    inspectP2pkh(
      serializeTransaction(tx),
      [{ transaction: s.prior }],
      s.pub,
      0,
    ),
    /unsupported-script/,
  );
  await assert.rejects(
    new DeviceIdentityKey(priv).signP2pkh(
      s.raw,
      [{ transaction: s.prior }],
      0,
      async () => false,
    ),
    /denied/,
  );
});
test("sequence, recipient, amount and locktime changes all alter actual signing digest", async () => {
  const s = await sample(),
    a = await inspectP2pkh(s.raw, [{ transaction: s.prior }], s.pub, 0);
  for (const mutate of [
    (t) => t.inputs[0].sequence++,
    (t) => t.locktime++,
    (t) => t.outputs[0].satoshis++,
    (t) =>
      (t.outputs[0].script = p2pkhScript(secp256k1.getPublicKey(3n, true))),
  ]) {
    const tx = structuredClone(s.tx);
    mutate(tx);
    const b = await inspectP2pkh(
      serializeTransaction(tx),
      [{ transaction: s.prior }],
      s.pub,
      0,
    );
    assert.equal(equal(a.digest, b.digest), false);
  }
});
