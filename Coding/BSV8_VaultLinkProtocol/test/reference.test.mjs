import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  decode,
  unhex,
  hex,
  transcript,
  pairingCode,
  deriveKeys,
  parseTransaction,
  p2pkhSighash,
} from "../dist/index.js";

test("independent Python v2 transcript, directional derivation and BIP143 vectors", async () => {
  const v = JSON.parse(
    await readFile(
      new URL("../../../test-vectors/v2/reference.json", import.meta.url),
      "utf8",
    ),
  );
  const t = await transcript(
    decode(unhex(v.helloHex)),
    decode(unhex(v.ackHex)),
  );
  assert.equal(hex(t), v.transcript);
  assert.equal(await pairingCode(t), v.pairingCode);
  const k = await deriveKeys(unhex(v.sharedHex), t);
  assert.equal(hex(k.c2sKey), v.keys["c2s-key"]);
  assert.equal(hex(k.s2cKey), v.keys["s2c-key"]);
  assert.equal(hex(k.c2sBaseNonce), v.keys["c2s-nonce"]);
  assert.equal(hex(k.s2cBaseNonce), v.keys["s2c-nonce"]);
  assert.equal(
    hex(
      await p2pkhSighash(parseTransaction(unhex(v.bip143.rawHex)), 0, {
        script: unhex(v.bip143.scriptHex),
        satoshis: BigInt(v.bip143.inputAmount),
      }),
    ),
    v.bip143.digest,
  );
});
