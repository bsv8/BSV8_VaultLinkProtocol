import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  encode,
  decode,
  hex,
  unhex,
  frame,
  FrameReader,
  crc32,
  Type,
  RecordCipher,
  hkdf,
  sharedSecret,
  HostHandshake,
  DeviceHandshake,
  RequestGate,
  commitment,
  verifyCommitment,
} from "../dist/index.js";
const vector = async (name) =>
  JSON.parse(
    await readFile(
      new URL("../../../test-vectors/" + name, import.meta.url),
      "utf8",
    ),
  );
test("CBOR executes legacy independent integer vectors and strict negatives", async () => {
  const v = await vector("cbor/cbor.json");
  let checks = 0;
  for (const c of v.cases) {
    for (const i of c.items ?? []) {
      if (typeof i.value === "number") {
        assert.equal(hex(encode(i.value)), i.expect);
        assert.equal(BigInt(decode(unhex(i.expect))), BigInt(i.value));
        checks++;
      }
    }
  }
  assert.ok(checks > 12);
  for (const s of [
    "1817",
    "190005",
    "f7",
    "c000",
    "9f00ff",
    "a2616200616100",
    "a2616100616101",
    "616100",
    "63eda080",
  ])
    assert.throws(() => decode(unhex(s)));
  const x = {
    z: 1,
    a: [{ b: 2, c: unhex("0102") }],
    big: 18446744073709551615n,
  };
  assert.equal(hex(encode(decode(encode(x)))), hex(encode(x)));
  assert.throws(() => encode({ x: "\ud800" }));
  assert.throws(() => encode(new Uint8Array(897)));
  assert.throws(() => encode({ x: 1.5 }));
});
test("v2 byte stream handles splits, noise, coalescing, exact capacity and bad CRC", () => {
  assert.equal(crc32(new TextEncoder().encode("123456789")), 0xcbf43926);
  const a = frame({
    type: Type.REQUEST,
    seq: 1,
    payload: new Uint8Array(1024),
  });
  for (let split = 0; split <= a.length; split++) {
    const r = new FrameReader();
    const out = [...r.feed(a.slice(0, split)), ...r.feed(a.slice(split))];
    assert.equal(out.length, 1);
    assert.equal(out[0].payload.length, 1024);
  }
  const r = new FrameReader();
  assert.equal(r.feed(Uint8Array.from([4, 5, 6, ...a, ...a])).length, 2);
  const bad = a.slice();
  bad[bad.length - 1] ^= 1;
  assert.equal(new FrameReader().feed(bad).length, 0);
  assert.throws(() => frame({ type: 0x13, seq: 2, payload: new Uint8Array() }));
});
test("RFC5869 HKDF is executed through WebCrypto", async () => {
  const v = await vector("crypto/crypto.json");
  for (const c of Object.values(v.hkdf))
    assert.equal(
      hex(
        await hkdf(
          unhex(c.ikmHex),
          unhex(c.saltHex),
          unhex(c.infoHex),
          c.okmHex.length / 2,
        ),
      ),
      c.okmHex,
    );
});
test("real X25519 and direction encryption bind entire handshake and close after tamper", async () => {
  const h = new HostHandshake(),
    pub = unhex(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
  const hello = await h.begin(
    { walletGeneration: 1, backendGeneration: 2, hostRunGeneration: 3 },
    [1],
  );
  const { ack, keys: d } = await new DeviceHandshake().acceptHello(
    hello,
    pub,
    4,
    5,
    [1],
  );
  const s = await h.acceptAck(ack, pub);
  assert.equal(s.pairingCode, d.pairingCode);
  assert.equal(hex(s.transcript), hex(d.transcript));
  const f = await s.send.seal(Type.REQUEST, encode({ x: 2 }));
  assert.equal(decode(await d.receive.open(f)).x, 2);
  const r = await d.send.seal(Type.RESPONSE, encode({ ok: true }));
  assert.equal(decode(await s.receive.open(r)).ok, true);
  const second = await s.send.seal(Type.REQUEST, encode({ x: 3 }));
  second.payload[0] ^= 1;
  await assert.rejects(d.receive.open(second));
  await assert.rejects(d.receive.open(second), /disconnected/);
});
test("record concurrent calls serialize nonce; gaps/replay and context replacement terminate", async () => {
  const key = new Uint8Array(32).fill(7),
    base = new Uint8Array(12).fill(4),
    ctx = { deviceRunId: 1, connectionId: 2 };
  const a = await RecordCipher.create(key, base, ctx),
    b = await RecordCipher.create(key, base, ctx);
  const packets = await Promise.all([
    a.seal(Type.REQUEST, Uint8Array.of(1)),
    a.seal(Type.REQUEST, Uint8Array.of(2)),
  ]);
  assert.deepEqual(
    packets.map((p) => p.seq),
    [1, 2],
  );
  assert.equal((await b.open(packets[0]))[0], 1);
  assert.equal((await b.open(packets[1]))[0], 2);
  await assert.rejects(b.open(packets[1]), /replay/);
  const c = await RecordCipher.create(key, base, ctx);
  await assert.rejects(c.open(packets[1]), /gap/);
});
test("single slot/high watermark: controls accessible, old result eviction never reexecutes", () => {
  const g = new RequestGate(),
    c = new Uint8Array(32).fill(3),
    r = (id) => ({ id, sessionId: "app", commitment: c });
  g.accept(r(1));
  assert.throws(() => g.accept(r(2)), /busy/);
  assert.equal(g.query(1, "app", c).state, "awaiting-user");
  g.start(1);
  assert.equal(g.cancel(1, c).state, "executing");
  g.complete(1, Uint8Array.of(8));
  assert.equal(g.accept(r(1)).state, "completed");
  g.accept(r(2));
  g.deny(2);
  assert.equal(g.query(1, "app", c), null);
  assert.throws(() => g.accept(r(1)), /replay/);
  assert.throws(
    () => g.accept({ ...r(2), commitment: new Uint8Array(32).fill(4) }),
    /conflict/,
  );
  g.invalidate();
  assert.throws(() => g.accept(r(3)), /disconnected/);
});
test("commitment recomputes actual canonical object, alteration fails", async () => {
  const c = await commitment("identity", 1, {
    purpose: "login",
    challenge: new Uint8Array(32),
  });
  await verifyCommitment(c, "identity", 1, {
    challenge: new Uint8Array(32),
    purpose: "login",
  });
  await assert.rejects(
    verifyCommitment(c, "identity", 1, {
      purpose: "pay",
      challenge: new Uint8Array(32),
    }),
  );
});
test("HELLO capability/connection tamper changes full transcript; wrong expected Key never pairs", async () => {
  const pub = unhex(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
    h = new HostHandshake();
  const hello = await h.begin(
    { walletGeneration: 1, backendGeneration: 2, hostRunGeneration: 3 },
    [1],
  );
  const { ack } = await new DeviceHandshake().acceptHello(hello, pub, 1, 2, [
    1,
  ]);
  const { transcript } = await import("../dist/index.js");
  const a = await transcript(hello, ack),
    b = await transcript(hello, { ...ack, connectionId: 3 });
  assert.notEqual(hex(a), hex(b));
  await assert.rejects(
    h.acceptAck(
      ack,
      unhex(
        "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      ),
    ),
    /wrong-key/,
  );
});
