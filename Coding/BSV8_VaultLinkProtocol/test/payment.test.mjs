import test from "node:test";
import assert from "node:assert/strict";
import {
  PaymentPolicy,
  externalOutputAmount,
  poolPaymentDelta,
} from "../dist/index.js";
const key =
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
// 真正执行保存/重载与拒绝语义；内存适配仅检验持久接口契约，不声称设备掉电通过。
class Store {
  value = null;
  fail = false;
  async load() {
    return structuredClone(this.value);
  }
  async save(s) {
    if (this.fail) throw Error("disk-failed");
    this.value = structuredClone(s);
  }
}
const cfg = (id = "one", kind = "app") => ({
  id,
  owner: "owner",
  kind,
  network: "main",
  paymentType: "p2pkh",
  enabled: true,
  singleLimit: 10n,
  defaultSessionLimit: 15n,
  revision: 1,
});
const pay = (id, amount, channelId = "one", kind = "app") => ({
  requestId: id,
  channelId,
  owner: "owner",
  kind,
  sessionId: kind === "app" ? "session" : null,
  network: "main",
  paymentType: "p2pkh",
  amount,
  commitment: new Uint8Array(32).fill(id.charCodeAt(0)),
});
const approval = (p, q, raise) => ({
  requestCommitment: p.commitment,
  configRevision: q.configRevision,
  sessionRevision: q.sessionRevision,
  ...(raise === undefined ? {} : { raiseSessionLimit: raise }),
});
async function ready() {
  const store = new Store(),
    p = await PaymentPolicy.open(store, key);
  await p.configure(cfg(), true);
  await p.startSession("session", "owner", true);
  return { p, store };
}
test("registration, ownership, config revision and first-enable confirmation", async () => {
  const store = new Store(),
    p = await PaymentPolicy.open(store, key);
  await assert.rejects(p.configure(cfg(), false), /confirmation/);
  await p.configure(cfg(), true);
  await assert.rejects(
    p.configure({ ...cfg(), singleLimit: 20n }, true),
    /stale/,
  );
  await assert.rejects(
    p.startSession("session", "owner", false),
    /confirmation/,
  );
  await p.startSession("session", "owner", true);
  await assert.rejects(p.quote({ ...pay("a", 1n), owner: "other" }), /channel/);
  await assert.rejects(p.quote(pay("a", 1n, "missing")), /channel/);
});
test("equal single/session thresholds auto; either excess requires single bound approval", async () => {
  const { p } = await ready();
  await p.reserve(pay("a", 10n));
  await p.markSigned("a");
  await p.reserve(pay("b", 5n));
  await p.markSigned("b");
  const c = pay("c", 1n),
    q = await p.quote(c);
  assert.deepEqual(q.reasons, ["session-limit"]);
  await assert.rejects(p.reserve(c), /confirmation/);
  await p.reserve(c, approval(c, q));
  await p.markSigned("c");
  assert.equal((await p.quote(pay("d", 1n))).used, 16n);
  assert.deepEqual((await p.quote(pay("d", 11n))).reasons, [
    "single-limit",
    "session-limit",
  ]);
});
test("raise applies only current session and never clears used/default/single threshold", async () => {
  const { p } = await ready();
  await p.reserve(pay("a", 10n));
  await p.markSigned("a");
  const b = pay("b", 10n),
    q = await p.quote(b);
  await p.reserve(b, approval(b, q, 30n));
  await p.markSigned("b");
  const s = await p.snapshot();
  assert.equal(s.sessions[0].used, 20n);
  assert.equal(s.sessions[0].limit, 30n);
  assert.equal(s.channels[0].defaultSessionLimit, 15n);
  assert.equal(s.channels[0].singleLimit, 10n);
  assert.deepEqual((await p.quote(pay("c", 11n))).reasons, [
    "single-limit",
    "session-limit",
  ]);
});
test("cross-channel atomic reservations prevent concurrent small payments evading session total", async () => {
  const { p } = await ready();
  await p.configure(cfg("two"), true);
  const results = await Promise.allSettled([
    p.reserve(pay("a", 10n)),
    p.reserve(pay("b", 10n, "two")),
  ]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal((await p.snapshot()).sessions[0].used, 10n);
});
test("signed/unknown retain budget, known-unexecuted release leaves replay tombstone", async () => {
  const { p } = await ready();
  await p.reserve(pay("a", 5n));
  await p.releaseUnexecuted("a");
  assert.equal((await p.snapshot()).sessions[0].used, 0n);
  await assert.rejects(p.reserve(pay("a", 5n)), /reuse/);
  await p.reserve(pay("b", 5n));
  await p.markUnknown("b");
  await assert.rejects(p.releaseUnexecuted("b"), /unknown/);
  assert.equal((await p.snapshot()).sessions[0].used, 5n);
});
test("restart invalidates old session; neither ID reuse nor refresh restores auto allowance", async () => {
  const { p, store } = await ready();
  await p.reserve(pay("a", 7n));
  await p.markSigned("a");
  const restored = await PaymentPolicy.open(store, key);
  await assert.rejects(restored.quote(pay("b", 1n)), /session/);
  await assert.rejects(
    restored.startSession("session", "owner", true),
    /reuse/,
  );
  await restored.startSession("new", "owner", true);
  assert.equal((await restored.snapshot()).sessions[0].used, 7n);
});
test("storage failure fail-closes, requests and mutable approval cannot bypass binding", async () => {
  const { p, store } = await ready();
  store.fail = true;
  await assert.rejects(p.reserve(pay("a", 1n)), /disk/);
  await assert.rejects(p.quote(pay("b", 1n)), /unavailable/);
  const { p: q } = await ready();
  const c = pay("c", 20n),
    quote = await q.quote(c);
  await assert.rejects(
    q.reserve(c, {
      ...approval(c, quote),
      requestCommitment: new Uint8Array(32).fill(1),
    }),
    /confirmation/,
  );
});
test("plugins have no session cumulative budget and money is BigInt; output-only ignores change", async () => {
  const store = new Store(),
    p = await PaymentPolicy.open(store, key);
  await p.configure(cfg("one", "plugin"), true);
  for (const id of ["a", "b", "c"]) {
    await p.reserve(pay(id, 10n, "one", "plugin"));
    await p.markSigned(id);
  }
  assert.equal((await p.snapshot()).sessions.length, 0);
  await assert.rejects(p.quote(pay("d", 10, "one", "plugin")), /amount/);
  assert.equal(
    externalOutputAmount([
      { amount: 9n, owned: false },
      { amount: 100n, owned: true },
    ]),
    9n,
  );
  assert.equal(poolPaymentDelta(100n, 109n), 9n);
  assert.throws(() => poolPaymentDelta(100n, 99n));
});
