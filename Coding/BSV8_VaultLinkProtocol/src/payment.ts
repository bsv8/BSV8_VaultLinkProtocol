import { addMoney, equal, fail, fixed, hex, money, MAX_U64 } from "./bytes.js";
export type OwnerKind = "app" | "plugin";
export interface ChannelConfig {
  id: string;
  owner: string;
  kind: OwnerKind;
  network: string;
  paymentType: string;
  enabled: boolean;
  singleLimit: bigint;
  defaultSessionLimit: bigint;
  revision: number;
}
interface Session {
  id: string;
  owner: string;
  limit: bigint;
  used: bigint;
  revision: number;
  active: boolean;
}
interface Pending {
  id: string;
  sessionId: string | null;
  channelId: string;
  amount: bigint;
  commitment: Uint8Array;
  configRevision: number;
  sessionRevision: number;
  state: "reserved" | "signed" | "unknown" | "released";
}
export interface PaymentInspection {
  requestId: string;
  channelId: string;
  owner: string;
  kind: OwnerKind;
  sessionId: string | null;
  network: string;
  paymentType: string;
  amount: bigint;
  commitment: Uint8Array;
}
export interface Quote {
  reasons: readonly ("disabled" | "single-limit" | "session-limit")[];
  amount: bigint;
  used: bigint;
  singleLimit: bigint;
  sessionLimit: bigint | null;
  configRevision: number;
  sessionRevision: number;
}
export interface Approval {
  requestCommitment: Uint8Array;
  configRevision: number;
  sessionRevision: number;
  raiseSessionLimit?: bigint;
}
export interface PolicySnapshot {
  version: 1;
  key: string;
  channels: ChannelConfig[];
  sessions: Session[];
  pending: Pending[];
}
/** 宿主必须保证原子持久替换成功才返回；失败/未知必须 throw，禁止降级到内存。 */
export interface PolicyStore {
  load(): Promise<PolicySnapshot | null>;
  save(snapshot: PolicySnapshot): Promise<void>;
}
const id = (s: string) => {
  if (typeof s !== "string" || !/^[a-zA-Z0-9._:/-]{1,96}$/.test(s))
    fail("invalid-id");
  return s;
};
function revision(n: number): void {
  if (!Number.isSafeInteger(n) || n < 1 || n >= 0xffffffff)
    fail("invalid-revision");
}
function config(c: ChannelConfig): ChannelConfig {
  id(c.id);
  id(c.owner);
  id(c.network);
  id(c.paymentType);
  if (c.kind !== "app" && c.kind !== "plugin") fail("invalid-owner");
  if (typeof c.enabled !== "boolean") fail("invalid-config");
  money(c.singleLimit);
  money(c.defaultSessionLimit);
  revision(c.revision);
  return { ...c };
}
/** 单实例执行权威。所有 read/check/reserve/commit 串行；存储失败后永久失效，防止不确定落盘后重用额度。 */
export class PaymentPolicy {
  private state: PolicySnapshot;
  private alive = true;
  private tail: Promise<unknown> = Promise.resolve();
  private constructor(
    private store: PolicyStore,
    key: string,
  ) {
    this.state = { version: 1, key, channels: [], sessions: [], pending: [] };
  }
  static async open(store: PolicyStore, key: string): Promise<PaymentPolicy> {
    if (!/^0[23][0-9a-f]{64}$/.test(key)) fail("invalid-key");
    const p = new PaymentPolicy(store, key);
    const old = await store.load();
    if (old) {
      p.validate(old, key);
      p.state = structuredClone(old);
      // 断电位置不可判断。保留占用，把旧预占转成未知，App/插件都不能续签。
      for (const s of p.state.sessions) s.active = false;
      for (const request of p.state.pending)
        if (request.state === "reserved") request.state = "unknown";
      await p.persist();
    }
    return p;
  }
  private run<T>(f: () => Promise<T>): Promise<T> {
    const p = this.tail.then(() => {
      if (!this.alive) fail("policy-unavailable");
      return f();
    });
    this.tail = p.catch(() => {});
    return p;
  }
  private async persist(): Promise<void> {
    try {
      await this.store.save(structuredClone(this.state));
    } catch (e) {
      this.alive = false;
      throw e;
    }
  }
  async configure(c: ChannelConfig, confirmed: boolean): Promise<void> {
    const copy = config(c);
    return this.run(async () => {
      const old = this.state.channels.find((x) => x.id === copy.id);
      if (
        old &&
        (old.owner !== copy.owner ||
          old.kind !== copy.kind ||
          old.network !== copy.network ||
          old.paymentType !== copy.paymentType)
      )
        fail("channel-conflict");
      if (
        (old && copy.revision !== old.revision + 1) ||
        (!old && copy.revision !== 1)
      )
        fail("stale-config");
      if (
        (!old ||
          (!old.enabled && copy.enabled) ||
          copy.singleLimit > old.singleLimit ||
          copy.defaultSessionLimit > old.defaultSessionLimit) &&
        confirmed !== true
      )
        fail("confirmation-required");
      if (!old && this.state.channels.length >= 32) fail("capacity");
      this.state.channels = this.state.channels.filter((x) => x.id !== copy.id);
      this.state.channels.push(copy);
      await this.persist();
    });
  }
  async startSession(
    sessionId: string,
    owner: string,
    confirmed: boolean,
  ): Promise<void> {
    id(sessionId);
    id(owner);
    return this.run(async () => {
      if (confirmed !== true) fail("confirmation-required");
      if (this.state.sessions.some((s) => s.id === sessionId))
        fail("session-reuse");
      if (this.state.sessions.length >= 16) fail("capacity");
      const channels = this.state.channels.filter(
        (x) => x.owner === owner && x.kind === "app" && x.enabled,
      );
      if (!channels.length) fail("unknown-owner");
      /* 多渠道只对应一个 App 默认会话额度，冲突时拒绝而不是偷偷选最大。 */ const limit =
        channels[0]!.defaultSessionLimit;
      if (channels.some((x) => x.defaultSessionLimit !== limit))
        fail("session-limit-conflict");
      this.state.sessions.push({
        id: sessionId,
        owner,
        limit,
        used: 0n,
        revision: 1,
        active: true,
      });
      await this.persist();
    });
  }
  async closeSession(sessionId: string): Promise<void> {
    return this.run(async () => {
      const s = this.session(sessionId);
      s.active = false;
      await this.persist();
    });
  }
  async quote(p: PaymentInspection): Promise<Quote> {
    const copy = this.inspectCopy(p);
    return this.run(async () => this.evaluate(copy));
  }
  async reserve(p: PaymentInspection, approval?: Approval): Promise<Quote> {
    const copy = this.inspectCopy(p);
    const a = approval
      ? { ...approval, requestCommitment: approval.requestCommitment.slice() }
      : undefined;
    return this.run(async () => {
      if (this.state.pending.some((x) => x.id === copy.requestId))
        fail("request-reuse");
      if (this.state.pending.length >= 256) fail("capacity");
      const q = this.evaluate(copy);
      if (q.reasons.length) {
        if (
          !a ||
          !equal(fixed(a.requestCommitment, 32), copy.commitment) ||
          a.configRevision !== q.configRevision ||
          a.sessionRevision !== q.sessionRevision
        )
          fail("confirmation-required");
      } else if (
        a &&
        (a.configRevision !== q.configRevision ||
          a.sessionRevision !== q.sessionRevision ||
          !equal(a.requestCommitment, copy.commitment))
      )
        fail("stale-approval");
      if (a?.raiseSessionLimit !== undefined) {
        if (copy.kind !== "app" || !copy.sessionId) fail("invalid-session");
        const s = this.session(copy.sessionId);
        money(a.raiseSessionLimit);
        if (
          !q.reasons.includes("session-limit") ||
          a.raiseSessionLimit < s.limit ||
          a.raiseSessionLimit < addMoney(q.used, copy.amount)
        )
          fail("invalid-limit");
        s.limit = a.raiseSessionLimit;
        s.revision++;
      }
      if (copy.kind === "app") {
        const s = this.session(copy.sessionId!);
        s.used = addMoney(
          s.used,
          copy.amount,
        ); /* used 包含预占。提高/确认不清零。 */
      }
      this.state.pending.push({
        id: copy.requestId,
        sessionId: copy.sessionId,
        channelId: copy.channelId,
        amount: copy.amount,
        commitment: copy.commitment.slice(),
        configRevision: q.configRevision,
        sessionRevision:
          copy.kind === "app" ? this.session(copy.sessionId!).revision : 0,
        state: "reserved",
      });
      await this.persist();
      return q;
    });
  }
  /** 在不可逆签名之前调用；配置/会话过期则拒绝，不能靠提前 quote 放行。 */
  async assertExecutable(requestId: string): Promise<void> {
    return this.run(async () => {
      const p = this.pending(requestId);
      if (p.state !== "reserved") fail("invalid-state");
      const c = this.state.channels.find((c) => c.id === p.channelId);
      if (!c || c.revision !== p.configRevision) fail("revoked");
      if (p.sessionId) {
        const s = this.session(p.sessionId);
        if (!s.active || s.revision !== p.sessionRevision) fail("revoked");
      }
    });
  }
  async markSigned(requestId: string): Promise<void> {
    return this.setState(requestId, "signed");
  }
  async markUnknown(requestId: string): Promise<void> {
    return this.setState(requestId, "unknown");
  }
  private async setState(
    requestId: string,
    state: "signed" | "unknown",
  ): Promise<void> {
    return this.run(async () => {
      const p = this.pending(requestId);
      if (p.state === "signed" && state === "unknown") return;
      if (p.state !== "reserved" && p.state !== state) fail("invalid-state");
      p.state = state;
      await this.persist();
    });
  }
  /** 只允许执行权威在确定未执行时释放；App/普通插件不得调用此内部方法。 */
  async releaseUnexecuted(requestId: string): Promise<void> {
    return this.run(async () => {
      const p = this.pending(requestId);
      if (p.state !== "reserved") fail("result-unknown");
      if (p.sessionId) {
        const s = this.session(p.sessionId);
        if (s.used < p.amount) fail("corrupt-state");
        s.used -= p.amount;
      }
      /* 保留墓碑防 requestId 再执行。 */ p.state = "released";
      await this.persist();
    });
  }
  async snapshot(): Promise<PolicySnapshot> {
    return this.run(async () => structuredClone(this.state));
  }
  lock(): void {
    this.alive = false;
  }
  private session(s: string): Session {
    const x = this.state.sessions.find((x) => x.id === s);
    if (!x) fail("invalid-session");
    return x;
  }
  private pending(s: string): Pending {
    const x = this.state.pending.find((x) => x.id === s);
    if (!x) fail("invalid-request");
    return x;
  }
  private inspectCopy(p: PaymentInspection): PaymentInspection {
    id(p.requestId);
    id(p.channelId);
    id(p.owner);
    id(p.network);
    id(p.paymentType);
    money(p.amount);
    if (p.amount === 0n) fail("invalid-amount");
    if (p.kind !== "app" && p.kind !== "plugin") fail("invalid-owner");
    if (p.sessionId !== null) id(p.sessionId);
    if (fixed(p.commitment, 32).every((x) => x === 0))
      fail("invalid-commitment");
    return { ...p, commitment: p.commitment.slice() };
  }
  private evaluate(p: PaymentInspection): Quote {
    const c = this.state.channels.find((x) => x.id === p.channelId);
    if (
      !c ||
      c.owner !== p.owner ||
      c.kind !== p.kind ||
      c.network !== p.network ||
      c.paymentType !== p.paymentType
    )
      fail("invalid-channel");
    const reasons: ("disabled" | "single-limit" | "session-limit")[] = [];
    if (!c.enabled) reasons.push("disabled");
    if (p.amount > c.singleLimit) reasons.push("single-limit");
    let s: Session | undefined;
    if (p.kind === "app") {
      if (!p.sessionId) fail("invalid-session");
      s = this.session(p.sessionId);
      if (!s.active || s.owner !== p.owner) fail("invalid-session");
      if (s.used > MAX_U64 - p.amount) fail("amount-overflow");
      if (s.used + p.amount > s.limit) reasons.push("session-limit");
    } else if (p.sessionId !== null) fail("invalid-session");
    return {
      reasons,
      amount: p.amount,
      used: s?.used ?? 0n,
      singleLimit: c.singleLimit,
      sessionLimit: s?.limit ?? null,
      configRevision: c.revision,
      sessionRevision: s?.revision ?? 0,
    };
  }
  private validate(s: PolicySnapshot, key: string): void {
    if (
      !s ||
      s.version !== 1 ||
      s.key !== key ||
      !Array.isArray(s.channels) ||
      !Array.isArray(s.sessions) ||
      !Array.isArray(s.pending) ||
      s.channels.length > 32 ||
      s.sessions.length > 16 ||
      s.pending.length > 256
    )
      fail("corrupt-state");
    const unique = (values: string[]) => {
      if (new Set(values).size !== values.length) fail("corrupt-state");
    };
    for (const c of s.channels) config(c);
    unique(s.channels.map((c) => c.id));
    for (const x of s.sessions) {
      id(x.id);
      id(x.owner);
      money(x.limit);
      money(x.used);
      revision(x.revision);
      if (typeof x.active !== "boolean") fail("corrupt-state");
    }
    unique(s.sessions.map((x) => x.id));
    for (const x of s.pending) {
      id(x.id);
      id(x.channelId);
      money(x.amount);
      fixed(x.commitment, 32);
      revision(x.configRevision);
      const channel = s.channels.find((c) => c.id === x.channelId);
      const session = s.sessions.find((t) => t.id === x.sessionId);
      if (
        !["reserved", "signed", "unknown", "released"].includes(x.state) ||
        !channel ||
        x.amount === 0n ||
        x.commitment.every((b) => b === 0) ||
        x.configRevision > channel.revision ||
        (channel.kind === "app"
          ? !session ||
            session.owner !== channel.owner ||
            !Number.isSafeInteger(x.sessionRevision) ||
            x.sessionRevision < 1 ||
            x.sessionRevision > session.revision
          : x.sessionId !== null || x.sessionRevision !== 0)
      )
        fail("corrupt-state");
    }
    unique(s.pending.map((x) => x.id));
    for (const session of s.sessions) {
      let accounted = 0n;
      for (const payment of s.pending)
        if (payment.sessionId === session.id && payment.state !== "released")
          accounted = addMoney(accounted, payment.amount);
      if (accounted !== session.used) fail("corrupt-state");
    }
  }
}
export interface Output {
  amount: bigint;
  owned: boolean;
}
/** owned 必须来自实际脚本与当前 Key 的核验，不使用主机 change 标记。矿工费不占额度。 */
export function externalOutputAmount(outputs: readonly Output[]): bigint {
  let total = 0n;
  for (const o of outputs) {
    money(o.amount);
    if (typeof o.owned !== "boolean") fail("invalid-output");
    if (!o.owned) total = addMoney(total, o.amount);
  }
  return total;
}
/** 费用池累计更新仅按核验后的对外付款增量；同池连续状态验证由 Profile 负责。 */
export function poolPaymentDelta(previous: bigint, next: bigint): bigint {
  money(previous);
  money(next);
  if (next < previous) fail("payment-rollback");
  return next - previous;
}
// 可用于日志关联的非秘密标识；不导出真实私钥或正文。
export const paymentCommitmentId = (b: Uint8Array): string => hex(fixed(b, 32));
