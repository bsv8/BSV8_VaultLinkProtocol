export { FaultTransport } from "./fault-transport.mjs";
import {
  commitment,
  inspectP2pkh,
  p2pkhScript,
  serializeTransaction,
  sha256d,
  unhex,
} from "../../src/index.ts";
import { secp256k1 } from "@noble/curves/secp256k1";
export const TEST_PUBLIC_KEY = unhex(
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
);
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const integer = (v) => BigInt(v);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function fixture(id, amount = 300n, channel = "one") {
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
    outputs: [{ satoshis: 1000n, script: p2pkhScript(TEST_PUBLIC_KEY) }],
    locktime: 0,
  });
  const rawTx = serializeTransaction({
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
        satoshis: amount,
        script: p2pkhScript(secp256k1.getPublicKey(2n, true)),
      },
      { satoshis: 990n - amount, script: p2pkhScript(TEST_PUBLIC_KEY) },
    ],
    locktime: 0,
  });
  const body = {
    rawTx,
    prevTransactions: [previous],
    channelId: channel,
    paymentId: id,
  };
  const review = await inspectP2pkh(
    rawTx,
    [{ transaction: previous }],
    TEST_PUBLIC_KEY,
    0,
  );
  return {
    body,
    review,
    hash: await commitment("bsv-payment", 1, {
      ...body,
      amount: review.amount,
    }),
  };
}
// 同一套序列由浏览器和原生互通检查运行。connector 必须创建真实 SDK 连接，不接受结果替身。
export async function runSuite(connector, onResult = () => {}) {
  const results = [];
  let client;
  let previousBoot;
  async function connect() {
    client = await connector.connect();
    void client.run();
    return client;
  }
  async function control(op, body = {}) {
    return client.execute(
      op,
      body,
      await commitment("test", 1, { op, body }),
      10000,
    );
  }
  async function ok(op, body = {}) {
    const value = await control(op, body);
    assert(!value.error, `${op}: ${value.error}`);
    return value;
  }
  async function configure(
    channel = "one",
    single = 400n,
    total = 500n,
    revision = 1,
    enabled = true,
  ) {
    return ok("test.configure", {
      channelId: channel,
      singleLimit: single,
      sessionLimit: total,
      revision,
      enabled,
    });
  }
  async function state(sessionId = "app-1", paymentId = "") {
    return ok("test.state", { sessionId, paymentId });
  }
  async function setup() {
    await ok("test.reset");
    await configure();
    await ok("test.session", { sessionId: "app-1" });
    await ok("test.authorize", { decision: "deny", raise: 0n });
  }
  async function pay(id, amount = 300n, channel = "one") {
    const f = await fixture(id, amount, channel),
      result = await client.execute("bsv.pay", f.body, f.hash, 10000);
    return { f, result };
  }
  function validSignature(result, f) {
    assert(!result.error, `payment: ${result.error}`);
    assert(integer(result.amount) === f.review.amount, "wrong output amount");
    assert(result.signatures?.length === 1, "wrong signature count");
    const sig = result.signatures[0];
    assert(sig.at(-1) === 0x41, "wrong sighash flag");
    assert(
      secp256k1.verify(sig.subarray(0, -1), f.review.digest, TEST_PUBLIC_KEY, {
        prehash: false,
        lowS: true,
      }),
      "independent signature verification failed",
    );
  }
  async function reconnect(expectedBootChange = true) {
    await client.close();
    client = undefined;
    await connector.reconnect(expectedBootChange);
    await connect();
    if (expectedBootChange)
      assert(
        client.sessionBinding.deviceRunId !== previousBoot,
        "device did not reboot",
      );
  }
  async function test(id, name, fn) {
    const start = performance.now();
    try {
      await fn();
      const row = {
        id,
        name,
        status: "passed",
        durationMs: Math.round(performance.now() - start),
      };
      results.push(row);
      await onResult(row);
    } catch (e) {
      const row = {
        id,
        name,
        status: "failed",
        error: String(e?.message ?? e),
        durationMs: Math.round(performance.now() - start),
      };
      results.push(row);
      await onResult(row);
      throw Object.assign(new Error(`${id}: ${row.error}`), { results });
    }
  }
  try {
    await test("E2E-01", "配对、持有权证明、加密往返与版本标识", async () => {
      await connect();
      const s = await state("", "");
      assert(s.testOnly === true, "not E2E firmware");
      assert(
        s.key ===
          Array.from(TEST_PUBLIC_KEY, (b) =>
            b.toString(16).padStart(2, "0"),
          ).join(""),
        "unexpected identity",
      );
      previousBoot = client.sessionBinding.deviceRunId;
    });
    await test(
      "E2E-02",
      "额度内真实 P2PKH 签名，输出计额不计矿工费",
      async () => {
        await setup();
        const { f, result } = await pay("auto");
        validSignature(result, f);
        assert(f.review.fee === 10n, "fixture fee differs");
        const s = await state("app-1", "auto");
        assert(
          integer(s.session.used) === 300n && integer(s.prompts) === 0n,
          "automatic policy differs",
        );
        assert(s.payment.state === "signed", "signature not committed");
      },
    );
    await test("E2E-03", "同付款 ID 重放不签署、不重复扣数", async () => {
      const { result } = await pay("auto");
      assert(result.error === "request-reuse", "replay accepted");
      assert(
        integer((await state()).session.used) === 300n,
        "replay changed budget",
      );
    });
    await test("E2E-04", "累计超额拒绝与仅批准本次", async () => {
      const denied = await pay("denied");
      assert(denied.result.error === "denied", "denial did not block");
      assert(
        integer((await state()).session.used) === 300n,
        "denial consumed quota",
      );
      await ok("test.authorize", { decision: "allow", raise: 0n });
      const once = await pay("once");
      validSignature(once.result, once.f);
      const s = await state();
      assert(
        integer(s.session.used) === 600n && integer(s.session.limit) === 500n,
        "one-time approval changed limit",
      );
    });
    await test("E2E-05", "提高当前累计额度，不改默认/单笔", async () => {
      await ok("test.authorize", { decision: "raise", raise: 1000n });
      const { f, result } = await pay("raise");
      validSignature(result, f);
      const s = await state();
      assert(
        integer(s.session.used) === 900n && integer(s.session.limit) === 1000n,
        "raise/reset differs",
      );
      assert(
        integer(s.channels[0].singleLimit) === 400n &&
          integer(s.channels[0].defaultSessionLimit) === 500n,
        "raise changed defaults",
      );
    });
    await test("E2E-06", "单笔等于额度免确认、超过额度拒绝", async () => {
      await setup();
      await configure("one", 400n, 1000n, 2);
      const { f, result } = await pay("equal", 400n);
      validSignature(result, f);
      assert(integer((await state()).prompts) === 0n, "equal limit prompted");
      assert(
        (await pay("single-excess", 401n)).result.error === "denied",
        "single excess ignored",
      );
    });
    await test("E2E-07", "App 跨渠道累计，换渠道不刷新额度", async () => {
      await setup();
      await configure("two");
      const { f, result } = await pay("first");
      validSignature(result, f);
      assert(
        (await pay("second", 300n, "two")).result.error === "denied",
        "cross-channel total ignored",
      );
    });
    await test("E2E-08", "交易证据和承诺篡改被拒绝", async () => {
      await setup();
      const f = await fixture("tamper");
      const bad = f.hash.slice();
      bad[0] ^= 1;
      assert(
        (await client.execute("bsv.pay", f.body, bad, 10000)).error ===
          "invalid-commitment",
        "wrong commitment accepted",
      );
      const prior = f.body.prevTransactions[0].slice();
      prior[10] ^= 1;
      const body = { ...f.body, prevTransactions: [prior] };
      assert(
        (await client.execute("bsv.pay", body, f.hash, 10000)).error ===
          "invalid-prevout",
        "wrong evidence accepted",
      );
      assert(
        integer((await state()).session.used) === 0n,
        "invalid payment counted",
      );
    });
    await test("E2E-09", "等待批准期间查询和取消，不产生签名", async () => {
      await setup();
      await ok("test.authorize", { decision: "wait", raise: 0n });
      const f = await fixture("cancel", 450n);
      const pending = client.submit("bsv.pay", f.body, f.hash, 10000);
      let waiting = false;
      for (let i = 0; i < 100; i++) {
        if ((await state()).waiting) {
          waiting = true;
          break;
        }
        await sleep(20);
      }
      assert(waiting, "authorization not waiting");
      const target = { requestId: pending.requestId, commitment: f.hash };
      const q = await client.execute(
        "system.query",
        target,
        await commitment("system", 1, target),
        10000,
      );
      assert(
        q.state === "awaiting-user",
        "query cannot reach pending operation",
      );
      const c = await client.execute(
        "system.cancel",
        target,
        await commitment("system", 1, target),
        10000,
      );
      assert(c.state === "cancelled", "cancel did not apply");
      assert(
        (await pending.result).error === "cancelled",
        "cancelled request delivered signature",
      );
      assert(
        integer((await state()).session.used) === 0n,
        "cancel consumed quota",
      );
    });
    await test("E2E-10", "等待批准时单业务槽拒绝并发付款", async () => {
      await setup();
      await ok("test.authorize", { decision: "wait", raise: 0n });
      const f = await fixture("waiting", 450n),
        pending = client.submit("bsv.pay", f.body, f.hash, 10000);
      for (let i = 0; i < 100; i++) {
        if ((await state()).waiting) break;
        await sleep(20);
      }
      assert(
        (await pay("busy", 450n)).result.error === "busy",
        "concurrent payment entered",
      );
      await ok("test.decide", { decision: "deny", raise: 0n });
      assert(
        (await pending.result).error === "denied",
        "decision not respected",
      );
    });
    for (const [i, phase, expected, status] of [
      [11, "before-reserve", 0n, null],
      [12, "after-reserve", 300n, "unknown"],
      [13, "after-sign", 300n, "unknown"],
      [14, "after-commit", 300n, "signed"],
    ]) {
      await test(`E2E-${i}`, `${phase} 内部重启与恢复`, async () => {
        await setup();
        previousBoot = client.sessionBinding.deviceRunId;
        await ok("test.arm", { phase });
        const f = await fixture(phase);
        let receivedSignature = false;
        try {
          const r = await client.execute("bsv.pay", f.body, f.hash, 12000);
          receivedSignature = !!r.signatures;
        } catch {
          /* 真实重启使旧请求结束，不能自动重发。 */
        }
        assert(
          !receivedSignature,
          "fault did not interrupt signature delivery",
        );
        await reconnect();
        const s = await state("app-1", phase);
        assert(
          s.session.active === false && integer(s.session.used) === expected,
          "restart restored authorization or cleared reservation",
        );
        assert(
          status === null ? s.payment === null : s.payment?.state === status,
          "recovery payment state differs",
        );
        assert(s.channels.length === 1, "restart lost configuration");
        assert(
          (await pay("old-session")).result.error === "invalid-session",
          "old App session revived",
        );
        await ok("test.session", { sessionId: "app-2" });
        if (status !== null)
          assert(
            (await pay(phase)).result.error === "request-reuse",
            "reboot allowed payment replay",
          );
      });
    }
    await test("E2E-15", "配置提交前重启保留旧配置", async () => {
      await setup();
      previousBoot = client.sessionBinding.deviceRunId;
      await ok("test.arm", { phase: "before-config" });
      try {
        await configure("one", 800n, 1000n, 2);
      } catch {}
      await reconnect();
      const s = await state();
      assert(
        integer(s.channels[0].revision) === 1n &&
          integer(s.channels[0].singleLimit) === 400n,
        "uncommitted config applied",
      );
    });
    await test("E2E-16", "配置提交后重启恢复新配置", async () => {
      await setup();
      previousBoot = client.sessionBinding.deviceRunId;
      await ok("test.arm", { phase: "after-config" });
      try {
        await configure("one", 800n, 1000n, 2);
      } catch {}
      await reconnect();
      const s = await state();
      assert(
        integer(s.channels[0].revision) === 2n &&
          integer(s.channels[0].singleLimit) === 800n,
        "committed config lost",
      );
    });
    await test("E2E-17", "实际持久接口失败停止自动支付", async () => {
      await setup();
      await ok("test.arm", { phase: "write-failure" });
      assert(
        (await pay("io-failure")).result.error === "storage-injected-failure",
        "write failure silently ignored",
      );
      assert(
        (await pay("after-failure")).result.error === "policy-unavailable",
        "storage failure fell back to memory",
      );
      previousBoot = client.sessionBinding.deviceRunId;
      await ok("test.arm", { phase: "restart" });
      await reconnect();
      const s = await state();
      assert(
        integer(s.session.used) === 0n && s.session.active === false,
        "failed reservation restored as committed",
      );
    });
    await test("E2E-18", "未知操作明确拒绝", async () => {
      const r = await client.execute(
        "unsupported.pay",
        {},
        await commitment("identity", 1, {}),
        10000,
      );
      assert(r.error === "unsupported", "unsupported returned success");
    });
    await test(
      "E2E-19",
      "真实加密记录篡改断链，不签名、不复活授权",
      async () => {
        await setup();
        const f = await fixture("bad-record");
        connector.corruptNextRequest();
        let signed = false;
        try {
          signed = !!(await client.execute("bsv.pay", f.body, f.hash, 12000))
            .signatures;
        } catch {}
        assert(!signed, "altered record delivered a signature");
        await reconnect(false);
        const s = await state("app-1", "bad-record");
        assert(
          s.session.active === false &&
            integer(s.session.used) === 0n &&
            s.payment === null,
          "record failure changed budget or kept authorization",
        );
      },
    );
    await test("E2E-20", "错 Key 与拒绝配对不能建立可用会话", async () => {
      await client.close();
      client = undefined;
      await connector.reconnect(false);
      let wrongKey = false;
      try {
        const unexpected = await connector.connect({
          expectedPublicKey: secp256k1.getPublicKey(2n, true),
        });
        await unexpected.close();
      } catch (e) {
        wrongKey = e.message.includes("wrong-key");
      }
      assert(
        wrongKey,
        "unexpected identity accepted or connection failed for unrelated reason",
      );
      await connector.reconnect(false);
      let denied = false;
      try {
        const unexpected = await connector.connect({ approvePairing: false });
        await unexpected.close();
      } catch (e) {
        denied = e.message.includes("pairing-denied");
      }
      assert(denied, "pairing refusal accepted or failed for unrelated reason");
      await connector.reconnect(false);
      await connect();
      assert(
        (await state("", "")).testOnly === true,
        "device unavailable after denied pairing",
      );
    });
    return {
      status: "passed",
      hardware: connector.hardware === true,
      transport: connector.label,
      protocolVersion: 2,
      deviceRunId: client.sessionBinding.deviceRunId,
      results,
    };
  } finally {
    await client?.close();
    await connector.close();
  }
}
