import {
  serializeTransaction,
  p2pkhScript,
  feePoolScript,
  parseTransaction,
  sha256,
  sha256d,
  hex,
  unhex,
} from "../../src/index.ts";
import { secp256k1 } from "@noble/curves/secp256k1";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const check = (v, m) => {
  if (!v) throw Error(m);
};
const businessRejected = (error) =>
  typeof error === "string" &&
  ![
    "result-unknown",
    "disconnected",
    "hardware-disconnected",
    "usb-lease-revoked",
  ].includes(error);
export const TEST_PUBLIC_KEY = hex(
  secp256k1.getPublicKey(
    unhex("18e14a8bf50f1e2a33445566778899aabbccddeeff0011223344556677889977"),
    true,
  ),
);
export async function waitFor(read, predicate, label, ms = 20000) {
  const deadline = Date.now() + ms;
  let last;
  while (Date.now() < deadline) {
    last = await read();
    if (predicate(last)) return last;
    await sleep(80);
  }
  throw Error("timeout: " + label + " " + JSON.stringify(last));
}
export async function enterTestPin(link, wrong = false) {
  const first = await link.status();
  check(Number(first.screen) === 1, "PIN entry must begin at lock screen");
  for (let i = 0; i < 8; i++) {
    const status = await link.status(),
      target = wrong && i === 7 ? 1 : 0,
      cursor = Number(status.pinCursor);
    const up = (target - cursor + 10) % 10,
      down = (cursor - target + 10) % 10;
    for (let j = 0; j < Math.min(up, down); j++)
      await link.press(up <= down ? 2 : 0, 220);
    const selected = await link.status();
    check(
      Number(selected.pinCursor) === target,
      "PIN cursor did not reach selected test digit",
    );
    await link.press(1, 220);
    if (i < 7)
      await waitFor(
        () => link.status(),
        (s) => Number(s.pinEntered) === i + 1,
        "PIN digit input",
      );
  }
  if (!wrong)
    await waitFor(
      () => link.status(),
      (s) => s.unlocked,
      "PIN unlock",
    );
}
export async function review(link, mode = "allow") {
  await waitFor(
    () => link.status(),
    (s) => s.ui.visible,
    "device review",
  );
  if (mode === "deny") {
    await link.press(0, 2000);
    console.info(
      "[RocKey E2E] denial button released: " +
        JSON.stringify(await link.status()),
    );
    return;
  }
  for (let n = 0; n < 160; n++) {
    const s = await link.status();
    check(!s.ui.pin, "fresh PIN review must use normal PIN entry");
    if (s.ui.read) break;
    await link.press(2);
    if (n === 159)
      throw Error("review too long: " + JSON.stringify(await link.status()));
  }
  check(!(await link.status()).ui.raise, "increase selected without a short B");
  if (mode === "raise") {
    const s = await link.status();
    check(s.ui.canRaise, "session increase unavailable");
    await link.press(1);
    // The injection acknowledgment precedes normal debounce and UI drawing.
    // Wait for the real controller state, rather than reading the first frame
    // while the release event is still pending.
    await waitFor(
      () => link.status(),
      (s) => s.ui.raise,
      "increase toggle",
    );
  }
  await link.press(1, 2000);
  check(
    (await link.status()).ui.raise === (mode === "raise"),
    "confirmation hold changed the selected increase option",
  );
}
export async function enroll(link, journey, { deny = false } = {}) {
  const opening = journey.enroll(link).then(
    (value) => ({ value }),
    (e) => {
      console.info("[RocKey E2E] enrollment failed: " + e.message);
      return { error: e.message };
    },
  );
  console.info("[RocKey E2E] waiting for host pairing");
  const state = await waitFor(
    () => journey.rpc("state"),
    (s) => s.status === "pairing",
    "host pairing",
  );
  // 当前配对单边由设备确认，正式连接服务已自动发送展示请求。
  // 浏览器只展示核对码，不再调用已删除的主机人工 pair 控制接口。
  console.info("[RocKey E2E] waiting for device pairing");
  const device = await waitFor(
    () => link.status(),
    (s) => s.ui.pairing,
    "device pairing",
  );
  check(device.ui.pairCode === state.pairingCode, "pairing code mismatch");
  console.info(
    "[RocKey E2E] applying device pairing " + (deny ? "denial" : "approval"),
  );
  try {
    await review(link, deny ? "deny" : "allow");
  } catch (e) {
    // 否决配对会让正式连接服务立即关闭 USB；长按仍靠设备 TTL 释放。
    // 仅容许此处的断链，随后必须核实真实协议的 pairing-denied，不能将超时当成功。
    if (
      !deny ||
      !link.stopped ||
      ![
        "test-link-closed",
        "test-link-unavailable",
        "test-device-disconnected",
      ].includes(e.message)
    )
      throw e;
  }
  const outcome = await opening;
  if (deny) {
    check(
      outcome.error === "pairing-denied",
      "device pairing denial did not produce pairing-denied: " + outcome.error,
    );
    return;
  }
  check(!outcome.error, outcome.error);
  check(outcome.value.status === "connected", "connection not authenticated");
  const document = await journey.rpc("document");
  check(document.publicKeyHex === TEST_PUBLIC_KEY, "unexpected test wallet");
  return document;
}
async function previous(pub, id) {
  return serializeTransaction({
    version: 1,
    inputs: [
      {
        txid: await sha256(new TextEncoder().encode(id)),
        vout: 0,
        script: Uint8Array.of(1),
        sequence: 0xffffffff,
      },
    ],
    outputs: [{ satoshis: 1000n, script: p2pkhScript(pub) }],
    locktime: 0,
  });
}
async function payment(
  pub,
  amount,
  channelId,
  sessionId,
  action = "sign-p2pkh",
) {
  const id = crypto.randomUUID(),
    prev = await previous(pub, id);
  const raw = serializeTransaction({
    version: 2,
    inputs: [
      {
        txid: await sha256d(prev),
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
      { satoshis: 990n - amount, script: p2pkhScript(pub) },
    ],
    locktime: 0,
  });
  return {
    action,
    channelId,
    sessionId,
    paymentId: id,
    rawTxHex: hex(raw),
    prevTransactionHexes: [hex(prev)],
  };
}
// 全链路结果由产品服务返回；硬件状态仅作为 UI/确认次数观察，不能提供签名结果。
export async function runJourney(
  link,
  journey,
  onResult = () => {},
  { poolsOnly = false } = {},
) {
  const results = [],
    runId = crypto.randomUUID(),
    pub = unhex(TEST_PUBLIC_KEY),
    session = runId;
  async function step(name, run) {
    if (poolsOnly && !name.includes("fee pool funding")) return;
    const start = Date.now();
    try {
      await run();
      const row = { name, status: "passed", ms: Date.now() - start };
      results.push(row);
      onResult(row);
    } catch (e) {
      const row = {
        name,
        status: "failed",
        error: e.message,
        ms: Date.now() - start,
      };
      results.push(row);
      onResult(row);
      e.results = results;
      throw e;
    }
  }
  const snapshot = () => link.status();
  async function decided(command, mode = "allow") {
    // 注册 rejection handler 后再等待 UI，防止取消/否决成为未处理 Promise。
    const pending = journey.payment(command).then(
      (value) => ({ value }),
      (e) => ({ error: e.message }),
    );
    console.info(
      "[RocKey E2E] review request: " +
        command.action +
        " " +
        (command.id ?? command.channel?.id ?? ""),
    );
    await review(link, mode);
    console.info(
      "[RocKey E2E] review after buttons: " +
        JSON.stringify(await link.status()),
    );
    const outcome = await pending;
    if (mode === "deny") {
      check(
        outcome.error === "denied",
        "denial must return denied: " + outcome.error,
      );
      return outcome;
    }
    check(!outcome.error, outcome.error);
    return outcome.value;
  }
  const owner = "rockey-e2e-app";
  async function configure(id, paymentType = "p2pkh", kind = "app") {
    const channels = await journey.payment({ action: "list" });
    let old = channels.find((c) => c.id === id);
    if (!old) {
      await decided({
        action: "register",
        id,
        owner,
        kind,
        network: "main",
        paymentType,
      });
      old = (await journey.payment({ action: "list" })).find(
        (c) => c.id === id,
      );
    }
    check(
      old?.owner === owner &&
        old.kind === kind &&
        old.paymentType === paymentType,
      "test channel identity mismatch",
    );
    // 主机设置能力已删除：先检查拒绝，然后只用真实按钮修改本机菜单。
    let hostError;
    try {
      await journey.payment({
        action: "configure",
        channel: {
          ...old,
          enabled: true,
          singleLimit: "400",
          defaultSessionLimit: kind === "app" ? "500" : "0",
          revision: old.revision + 1,
        },
      });
    } catch (e) {
      hostError = e.message;
    }
    check(
      hostError === "hardware-settings-local",
      "host must not configure wallet policy",
    );
    const signatures = await journey.payment({ action: "signing-list" });
    // 首次注册后重新读取，不能使用注册前缺少新记录的列表。
    const actualChannels = await journey.payment({ action: "list" });
    const selectedIndex =
      signatures.length + actualChannels.findIndex((c) => c.id === id);
    check(
      Number((await snapshot()).screen) === 9,
      "local settings must begin at product menu",
    );
    for (
      let n = 0;
      n < 11 && Number((await snapshot()).menuSelected) !== 10;
      n++
    )
      await link.press(2);
    check(
      Number((await snapshot()).menuSelected) === 10,
      "channel menu not selected",
    );
    await link.press(1);
    check(
      Number((await snapshot()).screen) === 17,
      "channel settings not opened",
    );
    for (let n = 0; n < selectedIndex; n++) await link.press(2);
    await link.press(1);
    const current = actualChannels.find((c) => c.id === id);
    if (!current.enabled) {
      await link.press(1);
      await link.press(2);
      await link.press(1, 2000);
    }
    // 无论是否修改模式，保证每个字段编辑从列表重新进入，不依赖前一个保存。
    if (current.enabled) await link.press(0, 2000);
    async function setAmount(field, previous, target) {
      if (previous === target) return;
      await link.press(1);
      for (let n = 0; n < field; n++) await link.press(2);
      await link.press(1);
      const from = previous.padStart(20, "0"),
        to = target.padStart(20, "0"),
        span = Math.max(previous.length, target.length);
      for (let n = 0; n < span; n++) {
        const at = 19 - n,
          up = (Number(to[at]) - Number(from[at]) + 10) % 10,
          down = (10 - up) % 10;
        for (let j = 0; j < Math.min(up, down); j++)
          await link.press(up <= down ? 2 : 0);
        if (n + 1 < span) await link.press(1);
      }
      await link.press(1, 2000);
    }
    await setAmount(1, current.singleLimit, "400");
    if (kind === "app") await setAmount(2, current.defaultSessionLimit, "500");
    await link.press(0, 2000);
    check(
      Number((await snapshot()).screen) === 9,
      "local settings did not return to menu",
    );
    const saved = (await journey.payment({ action: "list" })).find(
      (c) => c.id === id,
    );
    check(
      saved.enabled &&
        saved.singleLimit === "400" &&
        (kind !== "app" || saved.defaultSessionLimit === "500"),
      "local buttons did not persist actual limits",
    );
  }
  const used = async () =>
    BigInt((await journey.rpc("session-read", { id: session })).used);
  await step(
    "test firmware identity, self-test and isolated wallet",
    async () => {
      const s = await snapshot();
      check(
        s.firmware === "rockey-product-e2e-v1" &&
          s.isolated &&
          !s.selftestFailed,
        "wrong firmware or self-test failure",
      );
      check(s.unlocked, "wallet locked");
      check(s.publicKey === TEST_PUBLIC_KEY, "wrong public test key");
    },
  );
  await step(
    "configure two App channels and one plugin channel through device UI",
    async () => {
      await configure("e2e.app.one");
      await configure("e2e.app.two");
      await configure("e2e.plugin", "p2pkh", "plugin");
    },
  );
  await step("unregistered or absent spending channel is refused", async () => {
    for (const id of ["", "e2e.absent." + runId]) {
      let error;
      try {
        await journey.payment(await payment(pub, 1n, id, null));
      } catch (e) {
        error = e.message;
        console.info("[RocKey E2E] invalid channel rejected: " + error);
      }
      check(
        error &&
          !["result-unknown", "disconnected", "hardware-disconnected"].includes(
            error,
          ),
        "unregistered channel must return business rejection: " + error,
      );
    }
  });
  await step("App connection session limit confirmation", async () => {
    await decided({ action: "session-open", id: session, owner });
    check((await used()) === 0n, "fresh session not empty");
  });
  await step("within single/session limits: no review", async () => {
    const n = (await snapshot()).ui.reviews;
    const result = await journey.payment(
      await payment(pub, 300n, "e2e.app.one", session),
    );
    check(
      result.amount === "300" && result.signatures.length === 1,
      "missing real signature",
    );
    check((await snapshot()).ui.reviews === n, "automatic payment prompted");
    check((await used()) === 300n, "session ledger not charged");
  });
  await step(
    "equal cumulative limit across two channels: no review",
    async () => {
      const n = (await snapshot()).ui.reviews;
      await journey.payment(await payment(pub, 200n, "e2e.app.two", session));
      check((await snapshot()).ui.reviews === n, "equal limit prompted");
      check((await used()) === 500n, "channels did not share session total");
    },
  );
  await step(
    "over session total: deny produces no charge/signature",
    async () => {
      await decided(await payment(pub, 1n, "e2e.app.two", session), "deny");
      check((await used()) === 500n, "denial changed ledger");
    },
  );
  await step(
    "over session total: one-time approval keeps configured limit",
    async () => {
      await decided(await payment(pub, 100n, "e2e.app.one", session));
      const s = await journey.rpc("session-read", { id: session });
      check(
        BigInt(s.used) === 600n && BigInt(s.limit) === 500n,
        "one-time approval reset or increased limit",
      );
    },
  );
  await step("increase current session limit while confirming", async () => {
    await decided(await payment(pub, 100n, "e2e.app.two", session), "raise");
    const s = await journey.rpc("session-read", { id: session });
    check(
      BigInt(s.used) === 700n && BigInt(s.limit) >= 700n,
      "session increase missing",
    );
    const channels = await journey.payment({ action: "list" });
    check(
      channels
        .filter((c) => c.kind === "app" && c.owner === owner)
        .every((c) => c.defaultSessionLimit === "500"),
      "session increase changed future defaults",
    );
  });
  await step(
    "plugin single-limit equality remains automatic without total limit",
    async () => {
      const n = (await snapshot()).ui.reviews;
      for (let i = 0; i < 2; i++)
        await journey.payment(await payment(pub, 400n, "e2e.plugin", null));
      check(
        (await snapshot()).ui.reviews === n,
        "plugin cumulative spending prompted",
      );
    },
  );
  await step("completed paymentId cannot sign or charge twice", async () => {
    const command = await payment(pub, 10n, "e2e.plugin", null);
    await journey.payment(command);
    let error;
    try {
      await journey.payment(command);
    } catch (e) {
      error = e.message;
    }
    check(
      businessRejected(error),
      "reused paymentId must return business rejection: " + error,
    );
  });
  await step("plugin over single limit: deny then allow", async () => {
    await decided(await payment(pub, 401n, "e2e.plugin", null), "deny");
    const result = await decided(await payment(pub, 401n, "e2e.plugin", null));
    check(result.amount === "401", "over-single approval failed");
  });
  await step(
    "review requires scrolling; short B cannot authorize",
    async () => {
      const command = await payment(pub, 402n, "e2e.plugin", null);
      let settled = false;
      const pending = journey.payment(command).then(
        (value) => {
          settled = true;
          return { value };
        },
        (e) => {
          settled = true;
          return { error: e.message };
        },
      );
      const first = await waitFor(
        snapshot,
        (s) => s.ui.visible,
        "payment review",
      );
      check(!first.ui.read, "fixture must exercise scrolling");
      await link.press(1, 2000);
      check(
        !settled && (await snapshot()).ui.visible,
        "unread review authorized",
      );
      for (let i = 0; i < 160; i++) {
        if ((await snapshot()).ui.read) break;
        await link.press(2);
      }
      await link.press(1, 100);
      check(!settled, "short B authorized");
      await link.press(1, 2000);
      const result = await pending;
      check(!result.error, result.error);
    },
  );
  await step(
    "cancel pending App payment clears review and retains ledger",
    async () => {
      const before = await used(),
        cmd = await payment(pub, 401n, "e2e.app.one", session);
      const pending = journey.payment(cmd).then(
        (value) => ({ value }),
        (e) => ({ error: e.message }),
      );
      await waitFor(snapshot, (s) => s.ui.visible, "pending App review");
      await journey.payment({ action: "session-cancel", id: session });
      const error = (await pending).error;
      check(
        businessRejected(error),
        "cancelled payment must return business rejection: " + error,
      );
      await waitFor(snapshot, (s) => !s.ui.visible, "cancelled review clear");
      check((await used()) === before, "cancellation changed session total");
    },
  );
  await step("standard BSV payment uses product signing profile", async () => {
    await configure("e2e.standard", "bsv.standard", "plugin");
    const r = await journey.payment(
      await payment(pub, 200n, "e2e.standard", null, "sign-standard"),
    );
    check(
      r.signatures.length === 1 && r.amount === "200",
      "standard signing failed",
    );
  });
  for (const family of ["connect", "bitfs"])
    await step(
      family + " fee pool funding and cumulative incremental payment",
      async () => {
        const id =
          family === "connect"
            ? "connect." + "a".repeat(64) + ".feepool.connect.main"
            : "bitfs.buyer.main";
        await configure(id, "feepool." + family, "plugin");
        const peer = secp256k1.getPublicKey(2n, true),
          arbiter = secp256k1.getPublicKey(3n, true),
          keys = family === "connect" ? [peer, pub] : [pub, peer, arbiter],
          prev = await previous(pub, crypto.randomUUID());
        let funding = serializeTransaction({
          version: 1,
          inputs: [
            {
              txid: await sha256d(prev),
              vout: 0,
              script: new Uint8Array(),
              sequence: 0xfffffffe,
            },
          ],
          outputs: [
            { satoshis: 900n, script: feePoolScript(keys) },
            { satoshis: 90n, script: p2pkhScript(pub) },
          ],
          locktime: 0,
        });
        const base = {
          action: "sign-feepool",
          family,
          channelId: id,
          sessionId: null,
        };
        const funded = await journey.payment({
          ...base,
          stage: "fund",
          paymentId: crypto.randomUUID(),
          rawTxHex: hex(funding),
          prevTransactionHexes: [hex(prev)],
        });
        check(funded.amount === "0", "funding counted as spending");
        const tx = parseTransaction(funding),
          sig = unhex(funded.signatures[0]);
        tx.inputs[0].script = Uint8Array.from([
          sig.length,
          ...sig,
          pub.length,
          ...pub,
        ]);
        funding = serializeTransaction(tx);
        const txid = await sha256d(funding);
        for (const [paid, amount] of [
          [100n, 100n],
          [150n, 50n],
          [150n, 0n],
        ]) {
          const raw = serializeTransaction({
            version: 1,
            inputs: [
              { txid, vout: 0, script: new Uint8Array(), sequence: 0xfffffffe },
            ],
            outputs: keys.map((k) => ({
              satoshis:
                hex(k) === TEST_PUBLIC_KEY
                  ? 890n - paid
                  : hex(k) === hex(peer)
                    ? paid
                    : 0n,
              script: p2pkhScript(k),
            })),
            locktime: 0,
          });
          const r = await journey.payment({
            ...base,
            stage: "state",
            paymentId: crypto.randomUUID(),
            rawTxHex: hex(raw),
            prevTransactionHexes: [hex(funding)],
          });
          check(BigInt(r.amount) === amount, "pool increment incorrect");
        }
      },
    );
  await step(
    "close App connection retains total and forbids further payment",
    async () => {
      const before = await used();
      await journey.payment({ action: "session-close", id: session });
      const s = await journey.rpc("session-read", { id: session });
      check(
        !s.active && BigInt(s.used) === before,
        "closing session cleared ledger",
      );
      let error;
      try {
        await journey.payment(await payment(pub, 1n, "e2e.app.one", session));
      } catch (e) {
        error = e.message;
      }
      check(
        businessRejected(error),
        "closed session must return business rejection: " + error,
      );
    },
  );
  const finalDevice = await snapshot();
  check(
    !finalDevice.ui.fault &&
      !finalDevice.rxDropped &&
      !finalDevice.serialErrors,
    "firmware fault or USB receive error during journey: " +
      JSON.stringify(finalDevice),
  );
  return {
    status: "passed",
    hardware: true,
    finalDevice,
    scope:
      "Keymaster production Worker adapters → VLP SDK → real USB → RocKey product firmware/UI/LittleFS",
    runId,
    results,
    device: await snapshot(),
  };
}
