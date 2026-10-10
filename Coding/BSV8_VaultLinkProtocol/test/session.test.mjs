import test from "node:test";
import assert from "node:assert/strict";
import {
  connectHost, enrollHost,
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
test("concurrent large requests keep authenticated fragments contiguous and preserve the business slot", async () => {
  const [h,d]=wire(), key=new DeviceIdentityKey(priv);
  const ready=acceptDevice(d,key,51,52,async()=>true);
  const client=await connectHost(h,{walletGeneration:1,backendGeneration:1,hostRunGeneration:1},key.publicKey(),secpIdentityVerifier,async()=>true);
  const server=new DeviceServer(await ready,()=>key.close());
  server.register("identity.large",{profile:"identity",version:1,
    async verify(body){object(body,["id","raw"]);assert.equal(body.raw.length,12000);assert.ok(body.raw.every(b=>b===body.id));return body;},
    async authorize(){return true;},async execute(core){return {id:core.id};}});
  const loops=[server.run(),client.run()];
  try{
    const bodies=[1,2,3].map(id=>({id,raw:new Uint8Array(12000).fill(id)}));
    const hashes=await Promise.all(bodies.map(body=>commitment("identity",1,body)));
    const results=await Promise.all(bodies.map((body,i)=>client.execute("identity.large",body,hashes[i])));
    for(let i=0;i<results.length;i++)assert.ok(results[i].id===bodies[i].id || results[i].error==="busy");
    const pong=await client.execute("system.ping",{},await commitment("system",1,{op:"system.ping"}));
    assert.equal(pong.error,undefined);
  }finally{await client.close();await Promise.all(loops);}
});

test("first binding publishes only the device Key authenticated by both pairing and possession proof", async () => {
  const [host, device] = wire(), key = new DeviceIdentityKey(priv);
  let hostCode, deviceCode;
  const ready = acceptDevice(device, key, 1, 2, async code => {deviceCode = code; return true;});
  const verified = await enrollHost(host, {walletGeneration: 3, backendGeneration: 4, hostRunGeneration: 5},
    secpIdentityVerifier, async code => {hostCode = code; return true;});
  const session = await ready;
  assert.equal(hostCode, deviceCode);
  assert.deepEqual(verified.publicKey, key.publicKey());
  const server = new DeviceServer(session, () => key.close());
  const loops = [server.run(), verified.client.run()];
  await verified.client.close(); await Promise.all(loops);
});

test("real encrypted byte streams deliver fragmented results and retain no one-time result bytes", async () => {
  const [host, device] = wire(), key = new DeviceIdentityKey(priv);
  const ready = acceptDevice(device, key, 61, 62, async () => true);
  const client = await connectHost(host, { walletGeneration: 1, backendGeneration: 1, hostRunGeneration: 1 }, key.publicKey(), secpIdentityVerifier, async () => true);
  const server = new DeviceServer(await ready, () => key.close());
  const { sha256, decode } = await import("../dist/index.js");
  let oneTime;
  // This exercises the actual SDK message layer, not a wallet operation or
  // physical approval. The returned digest is computed from the received bytes.
  for (const [operation, retainResult] of [["bytes.roundtrip", true], ["bytes.one-time", false]]) {
    server.register(operation, { profile: "byte-stream-test", version: 1, retainResult,
      async verify(body) { object(body, ["raw"]); assert.equal(body.raw.length, 8192); return body; },
      async authorize() { return true; },
      async execute(core) {
        const digest = await sha256(core.raw);
        if (!retainResult) { oneTime = digest; return { digest }; }
        return { raw: core.raw.slice(), digest };
      },
    });
  }
  const loops = [server.run(), client.run()], body = { raw: crypto.getRandomValues(new Uint8Array(8192)) };
  const hash = await commitment("byte-stream-test", 1, body), expected = await sha256(body.raw);
  try {
    const roundtrip = client.submit("bytes.roundtrip", body, hash);
    const result = await roundtrip.result;
    assert.deepEqual(result.raw, body.raw); assert.deepEqual(result.digest, expected);
    const query = { requestId: roundtrip.requestId, commitment: hash };
    const status = await client.execute("system.query", query, await commitment("system", 1, query));
    assert.equal(status.state, "completed"); assert.deepEqual(decode(status.payload, 32768).raw, body.raw);
    const secret = client.submit("bytes.one-time", body, hash);
    assert.deepEqual((await secret.result).digest, expected);
    const reference = { requestId: secret.requestId, commitment: hash };
    const final = await client.execute("system.query", reference, await commitment("system", 1, reference));
    assert.equal(final.state, "completed"); assert.equal(final.payload, null);
    assert.ok(oneTime.every(byte => byte === 0));
  } finally { await client.close(); await Promise.all(loops); }
});

test("closing an encrypted session during a one-time operation wipes a late private result and publishes none",async()=>{
 const [host,device]=wire(),key=new DeviceIdentityKey(priv);
 const ready=acceptDevice(device,key,71,72,async()=>true);
 const client=await connectHost(host,{walletGeneration:1,backendGeneration:1,hostRunGeneration:1},key.publicKey(),secpIdentityVerifier,async()=>true);
 const server=new DeviceServer(await ready,()=>key.close());
 let entered,release;const started=new Promise(r=>entered=r),wait=new Promise(r=>release=r);
 const secret=crypto.getRandomValues(new Uint8Array(32));
 server.register('bytes.one-time',{profile:'one-time-close',version:1,retainResult:false,
  async verify(body){object(body,[]);return body;},async authorize(){return true;},
  async execute(){entered();await wait;return {privateKey:secret};}});
 const loops=[server.run(),client.run()];
 const result=client.execute('bytes.one-time',{},await commitment('one-time-close',1,{}));
 const rejected=assert.rejects(result);await started;
 try{await server.close();release();await rejected;await new Promise(setImmediate);assert.ok(secret.every(b=>b===0));}
 finally{release();await client.close();await Promise.all(loops);}
});
