import { equal, fail, ProtocolError } from "./bytes.js";
import { decode, encode, object, type Value } from "./cbor.js";
import { commitment } from "./crypto.js";
import { Type } from "./frame.js";
import { RequestGate } from "./requests.js";
import { type ReadySession } from "./session.js";
export interface OperationHandler {
  profile: string;
  version: number;
  /** verify 返回 Profile 完整规范核心，禁止主机挑选字段。 */ verify(
    body: Value,
  ): Promise<Value>;
  authorize(core: Value, signal: AbortSignal): Promise<boolean>;
  execute(core: Value, signal: AbortSignal): Promise<Value>;
}
/** SDK 只登记真实操作。设备持续读取控制消息，业务执行不阻塞取消/状态查询；单业务槽由 Gate 强制。 */
export class DeviceServer {
  private gate = new RequestGate();
  private stopped = false;
  private active: Promise<void> | undefined;
  private operations = new Map<string, OperationHandler>();
  private abort: AbortController | undefined;
  constructor(
    private session: ReadySession,
    private onLock: () => void | Promise<void>,
  ) {}
  register(op: string, handler: OperationHandler): void {
    if (this.operations.has(op) || op.startsWith("system."))
      fail("invalid-operation");
    this.operations.set(op, handler);
  }
  async run(): Promise<void> {
    try {
      while (!this.stopped) {
        const f = await this.session.link.read(8000);
        if (f.type !== Type.REQUEST) fail("invalid-message");
        const r = object(decode(await this.session.keys.receive.open(f)), [
          "op",
          "opVersion",
          "body",
          "requestId",
          "binding",
          "commitment",
        ]);
        this.checkBinding(r.binding!);
        if (
          typeof r.op !== "string" ||
          r.opVersion !== 1 ||
          typeof r.requestId !== "number" ||
          !(r.commitment instanceof Uint8Array)
        )
          fail("invalid-request");
        if (r.op.startsWith("system.")) {
          await this.control(r);
          continue;
        }
        if (this.active) {
          await this.respond(r, { error: "busy" });
          continue;
        }
        this.active = this.business(r)
          .catch(() => this.close())
          .finally(() => {
            this.active = undefined;
          });
      }
    } catch {
      await this.close();
    }
  }
  private async business(r: Record<string, Value>): Promise<void> {
    try {
      const handler = this.operations.get(r.op as string);
      if (!handler) fail("unsupported");
      const core = await handler.verify(r.body!);
      if (this.stopped) fail("revoked");
      const computed = await commitment(handler.profile, handler.version, core);
      if (!equal(computed, r.commitment as Uint8Array))
        fail("invalid-commitment");
      const accepted = this.gate.accept({
        id: r.requestId as number,
        sessionId: this.session.binding.sessionId,
        commitment: computed,
      });
      if (accepted.state !== "awaiting-user") {
        await this.respond(
          r,
          accepted.payload
            ? decode(accepted.payload)
            : { state: accepted.state },
        );
        return;
      }
      this.abort = new AbortController();
      if (!(await handler.authorize(core, this.abort.signal))) {
        if (this.stopped) return;
        if (this.abort.signal.aborted) {
          await this.respond(r, { error: "cancelled" });
          return;
        }
        this.gate.deny(r.requestId as number);
        await this.respond(r, { error: "denied" });
        return;
      }
      if (this.stopped || this.abort.signal.aborted) return;
      this.gate.start(r.requestId as number);
      const result = await handler.execute(core, this.abort.signal);
      if (this.stopped) return;
      this.gate.complete(r.requestId as number, encode(result));
      await this.respond(r, result);
    } catch (e) {
      if (!this.stopped) {
        try {
          this.gate.unknown(r.requestId as number);
        } catch {
          /* 未接收请求没有执行槽，错误不制造完成结果。 */
        }
        await this.respond(r, {
          error: e instanceof ProtocolError ? e.code : "result-unknown",
        });
      }
    }
  }
  private async control(r: Record<string, Value>): Promise<void> {
    if (r.op === "system.ping") {
      await this.respond(r, { alive: true });
      return;
    }
    if (r.op === "system.lock" || r.op === "system.close") {
      await this.close();
      return;
    }
    if (r.op !== "system.query" && r.op !== "system.cancel") {
      await this.respond(r, { error: "unsupported" });
      return;
    }
    try {
      const b = object(r.body!, ["requestId", "commitment"]);
      if (
        typeof b.requestId !== "number" ||
        !(b.commitment instanceof Uint8Array)
      )
        fail("invalid-request");
      const result =
        r.op === "system.query"
          ? this.gate.query(
              b.requestId,
              this.session.binding.sessionId,
              b.commitment,
            )
          : this.gate.cancel(b.requestId, b.commitment);
      if (r.op === "system.cancel" && result?.state === "cancelled")
        this.abort?.abort();
      await this.respond(
        r,
        result
          ? { state: result.state, payload: result.payload }
          : { state: "unknown", payload: null },
      );
    } catch (e) {
      await this.respond(r, {
        error: e instanceof ProtocolError ? e.code : "result-unknown",
      });
    }
  }
  private checkBinding(value: Value): void {
    const b = object(value, [
      "sessionId",
      "sessionEpoch",
      "connectionId",
      "deviceRunId",
    ]);
    if (Object.entries(this.session.binding).some(([k, v]) => b[k] !== v))
      fail("stale-session");
  }
  private async respond(
    r: Record<string, Value>,
    payload: Value,
  ): Promise<void> {
    await this.session.link.send(
      await this.session.keys.send.seal(
        Type.RESPONSE,
        encode({
          requestId: r.requestId!,
          binding: this.session.binding as unknown as Value,
          commitment: r.commitment!,
          payload,
        }),
      ),
    );
  }
  async close(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    this.abort?.abort();
    this.gate.invalidate();
    this.session.keys.send.close();
    this.session.keys.receive.close();
    try {
      await this.onLock();
    } finally {
      await this.session.link.transport.close();
    }
  }
}
