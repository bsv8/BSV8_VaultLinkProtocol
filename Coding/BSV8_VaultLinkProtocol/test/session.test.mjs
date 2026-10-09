import test from "node:test";
import assert from "node:assert/strict";
import {
  connectHost,
  acceptDevice,
  DeviceIdentityKey,
  secpIdentityVerifier,
  DeviceServer,
  commitment,
  unhex,
  object,
} from "../dist/index.js";
// 真实 WHATWG 字节流，不用返回成功的握手/签名替身；两端执行同一生产状态机与密码实现。
function wire() {
  const ab = new TransformStream(),
    ba = new TransformStream();
  const make = (r, w) => {
    const reader = r.getReader(),
      writer = w.getWriter();
    let closed = false;
    return {
      async read() {
        const x = await reader.read();
        return x.done ? null : x.value;
      },
      async write(b) {
        await writer.write(b.slice());
      },
      async close() {
        if (closed) return;
        closed = true;
        await Promise.allSettled([reader.cancel(), writer.abort()]);
      },
    };
  };
  return [make(ba.readable, ab.writable), make(ab.readable, ba.writable)];
}
const priv = unhex(
  "0000000000000000000000000000000000000000000000000000000000000001",
);
test("full physical-pairing callbacks, possession proof, encrypted request and response roundtrip", async () => {
  const [host, device] = wire(),
    key = new DeviceIdentityKey(priv);
  let hostCode, deviceCode;
  const ready = acceptDevice(device, key, 1, 2, async (c) => {
    deviceCode = c;
    return true;
  });
  const client = await connectHost(
    host,
    { walletGeneration: 3, backendGeneration: 4, hostRunGeneration: 5 },
    key.publicKey(),
    secpIdentityVerifier,
    async (c) => {
      hostCode = c;
      return true;
    },
  );
  assert.equal(hostCode, deviceCode);
  const session = await ready,
    server = new DeviceServer(session, () => key.close());
  let executed = 0;
  server.register("identity.test", {
    profile: "identity",
    version: 1,
    async verify(body) {
      object(body, ["purpose"]);
      return body;
    },
    async authorize() {
      return true;
    },
    async execute(core) {
      executed++;
      return { purpose: core.purpose, done: true };
    },
  });
  const loops = [server.run(), client.run()];
  const body = { purpose: "test" };
  const result = await client.execute(
    "identity.test",
    body,
    await commitment("identity", 1, body),
  );
  assert.equal(result.done, true);
  assert.equal(executed, 1);
  const unsupported = await client.execute(
    "evidence.receive",
    {},
    await commitment("evidence", 1, {}),
  );
  assert.equal(unsupported.error, "unsupported");
  await client.close();
  await Promise.all(loops);
  assert.throws(() => key.publicKey(), /locked/);
});
test("pairing refusal does not grant a usable session", async () => {
  const [h, d] = wire(),
    key = new DeviceIdentityKey(priv);
  const device = acceptDevice(d, key, 11, 12, async () => false);
  const host = connectHost(
    h,
    { walletGeneration: 1, backendGeneration: 1, hostRunGeneration: 1 },
    key.publicKey(),
    secpIdentityVerifier,
    async () => true,
  );
  const results = await Promise.allSettled([device, host]);
  assert.ok(results.every((r) => r.status === "rejected"));
  key.close();
});
test("control query/cancel stays reachable while real authorization is awaiting, no execution", async () => {
  const [h, d] = wire(),
    key = new DeviceIdentityKey(priv);
  const ready = acceptDevice(d, key, 21, 22, async () => true);
  const client = await connectHost(
    h,
    { walletGeneration: 1, backendGeneration: 1, hostRunGeneration: 1 },
    key.publicKey(),
    secpIdentityVerifier,
    async () => true,
  );
  const server = new DeviceServer(await ready, () => key.close());
  let entered;
  const waiting = new Promise((r) => (entered = r));
  let executed = 0;
  server.register("content.test", {
    profile: "content",
    version: 1,
    async verify(body) {
      return body;
    },
    async authorize(_core, signal) {
      entered();
      return new Promise((resolve) =>
        signal.addEventListener("abort", () => resolve(false), { once: true }),
      );
    },
    async execute() {
      executed++;
      return { done: true };
    },
  });
  const loops = [server.run(), client.run()];
  const body = { purpose: "read" },
    c = await commitment("content", 1, body);
  const pending = client.execute("content.test", body, c, 250);
  await waiting;
  const target = { requestId: 1, commitment: c };
  const state = await client.execute(
    "system.query",
    target,
    await commitment("system", 1, target),
  );
  assert.equal(state.state, "awaiting-user");
  const cancelled = await client.execute(
    "system.cancel",
    target,
    await commitment("system", 1, target),
  );
  assert.equal(cancelled.state, "cancelled");
  await pending.catch(() => {});
  assert.equal(executed, 0);
  await client.close();
  await Promise.all(loops);
});
