import { fail } from "./bytes.js";
import { object, type Value } from "./cbor.js";
import { commitment } from "./crypto.js";
import { DeviceIdentityKey, inspectP2pkh } from "./bsv.js";
import {
  type Approval,
  PaymentPolicy,
  type PaymentInspection,
  type Quote,
} from "./payment.js";
import { type OperationHandler } from "./device.js";
/** 同一个实际交易只预占一次；所有输入共用一次授权。宿主负责原子绑定 policy 的 Key 与本 DeviceKey。 */
export class P2pkhPaymentOperation implements OperationHandler {
  readonly profile = "bsv-payment";
  readonly version = 1;
  constructor(
    private key: DeviceIdentityKey,
    private policy: PaymentPolicy,
    private context: {
      owner: string;
      kind: "app" | "plugin";
      sessionId: string | null;
    },
    private confirm: (
      request: PaymentInspection,
      quote: Quote,
      signal: AbortSignal,
    ) => Promise<{ allow: boolean; raiseSessionLimit?: bigint }>,
  ) {}
  async verify(body: Value): Promise<Value> {
    const b = object(body, [
      "rawTx",
      "prevTransactions",
      "channelId",
      "paymentId",
    ]);
    if (
      !(b.rawTx instanceof Uint8Array) ||
      !Array.isArray(b.prevTransactions) ||
      b.prevTransactions.some((v) => !(v instanceof Uint8Array)) ||
      typeof b.channelId !== "string" ||
      typeof b.paymentId !== "string"
    )
      fail("invalid-request");
    const frozen = structuredClone(b);
    const review = await inspectP2pkh(
      frozen.rawTx as Uint8Array,
      (frozen.prevTransactions as Uint8Array[]).map((transaction) => ({
        transaction,
      })),
      this.key.publicKey(),
      0,
    );
    if (!review.amount) fail("invalid-amount");
    /* Profile 不接收主机自报 amount/change，实际输出重新核算。 */ return {
      rawTx: frozen.rawTx!,
      prevTransactions: frozen.prevTransactions!,
      channelId: frozen.channelId!,
      paymentId: frozen.paymentId!,
      amount: review.amount,
    };
  }
  private async request(core: Value): Promise<PaymentInspection> {
    const b = object(core, [
      "rawTx",
      "prevTransactions",
      "channelId",
      "paymentId",
      "amount",
    ]);
    if (typeof b.amount !== "bigint") fail("invalid-amount");
    return {
      requestId: b.paymentId as string,
      channelId: b.channelId as string,
      ...this.context,
      network: "main",
      paymentType: "p2pkh",
      amount: b.amount,
      commitment: await commitment(this.profile, 1, core),
    };
  }
  async authorize(core: Value, signal: AbortSignal): Promise<boolean> {
    const p = await this.request(core),
      q = await this.policy.quote(p);
    let approval: Approval | undefined;
    if (q.reasons.length) {
      const answer = await this.confirm(
        structuredClone(p),
        structuredClone(q),
        signal,
      );
      if (!answer.allow || signal.aborted) return false;
      approval = {
        requestCommitment: p.commitment,
        configRevision: q.configRevision,
        sessionRevision: q.sessionRevision,
        ...(answer.raiseSessionLimit === undefined
          ? {}
          : { raiseSessionLimit: answer.raiseSessionLimit }),
      };
    }
    if (signal.aborted) return false;
    await this.policy.reserve(p, approval);
    if (signal.aborted) {
      await this.policy.releaseUnexecuted(p.requestId);
      return false;
    }
    return true;
  }
  async execute(core: Value, signal: AbortSignal): Promise<Value> {
    const p = await this.request(core),
      b = core as Record<string, Value>;
    let signatures: Uint8Array[];
    try {
      await this.policy.assertExecutable(p.requestId);
      if (signal.aborted) fail("revoked");
      signatures = await this.key.signAllP2pkh(
        b.rawTx as Uint8Array,
        (b.prevTransactions as Uint8Array[]).map((transaction) => ({
          transaction,
        })),
        signal,
        () => this.policy.assertExecutable(p.requestId),
      );
    } catch (e) {
      await this.policy.releaseUnexecuted(p.requestId);
      throw e;
    }
    /* 从此开始可能已有可花钱签名。落盘失败不释放额度，不交付签名。 */ await this.policy.markSigned(
      p.requestId,
    );
    return { signatures, amount: p.amount };
  }
}
