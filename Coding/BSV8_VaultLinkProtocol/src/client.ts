import { equal, fail, fixed, u32 } from "./bytes.js";
import { decode, encode, object, type Value } from "./cbor.js";
import { FrameReader, frame, Type } from "./frame.js";
import { commitment, type RecordCipher } from "./crypto.js";
import { type Transport } from "./transport.js";
export interface Binding {
  sessionId: string;
  sessionEpoch: number;
  connectionId: number;
  deviceRunId: number;
}
interface Waiting {
  resolve: (v: Value) => void;
  reject: (e: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
  commitment: Uint8Array;
  binding: Binding;
}
/** 此类只接受已完成配对/持有权验证的会话；生命周期由宿主显式绑定，不伪造 connected。 */
export class ProtocolClient {
  private nextId = 1;
  private pending = new Map<number, Waiting>();
  private reader = new FrameReader();
  private closed = false;
  private lastEvent = 0;
  private running = false;
  constructor(
    private transport: Transport,
    private send: RecordCipher,
    private receive: RecordCipher,
    private binding: Binding,
    private onEvent: (v: Value) => void = () => {},
  ) {
    u32(binding.sessionEpoch);
    u32(binding.deviceRunId);
    u32(binding.connectionId);
    if (!binding.sessionId) fail("invalid-session");
  }
  async run(): Promise<void> {
    if (this.running || this.closed) fail("invalid-state");
    this.running = true;
    const heartbeat = setInterval(() => {
      void commitment("system", 1, { op: "system.ping" })
        .then((c) => this.execute("system.ping", {}, c, 4000))
        .catch((e) => this.close(e));
    }, 1000);
    try {
      while (!this.closed) {
        const chunk = await this.transport.read();
        if (chunk === null) fail("disconnected");
        for (const f of this.reader.feed(chunk)) {
          const v = decode(await this.receive.open(f));
          if (f.type === Type.EVENT) {
            const e = object(v, ["kind", "eventSeq", "binding", "payload"]);
            this.checkBinding(e.binding!);
            if (typeof e.eventSeq !== "number" || e.eventSeq <= this.lastEvent)
              continue;
            u32(e.eventSeq);
            this.lastEvent = e.eventSeq;
            this.onEvent(e.payload!);
            continue;
          }
          if (f.type !== Type.RESPONSE) fail("invalid-response");
          const r = object(v, [
            "requestId",
            "binding",
            "commitment",
            "payload",
          ]);
          this.checkBinding(r.binding!);
          if (typeof r.requestId !== "number") fail("invalid-response");
          const p = this.pending.get(r.requestId);
          if (!p) continue;
          if (
            !(r.commitment instanceof Uint8Array) ||
            !equal(r.commitment, p.commitment)
          )
            fail("invalid-commitment");
          clearTimeout(p.timer);
          this.pending.delete(r.requestId);
          p.resolve(r.payload!);
        }
      }
    } catch (e) {
      await this.close(e);
    } finally {
      clearInterval(heartbeat);
    }
  }
  /** 只读绑定用于重连核验/诊断，不泄露任何链路密钥。 */
  get sessionBinding(): Binding {
    return { ...this.binding };
  }
  execute(
    op: string,
    body: Value,
    commitment: Uint8Array,
    timeoutMs = 120000,
  ): Promise<Value> {
    return this.submit(op, body, commitment, timeoutMs).result;
  }
  /** 返回实际分配的 ID，使 query/cancel 不需要猜测心跳占用的编号。 */
  submit(
    op: string,
    body: Value,
    commitment: Uint8Array,
    timeoutMs = 120000,
  ): { requestId: number; result: Promise<Value> } {
    if (this.closed) fail("disconnected");
    if (
      !/^[a-z][a-z0-9.-]{0,47}$/.test(op) ||
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1
    )
      fail("invalid-request");
    if (this.pending.size >= 32) fail("busy");
    if (this.nextId > 0xffffffff) fail("request-id-exhausted");
    const requestId = this.nextId++;
    const c = fixed(commitment, 32).slice();
    if (c.every((x) => x === 0)) fail("invalid-commitment");
    const payload = encode({
      op,
      opVersion: 1,
      body,
      requestId,
      binding: this.binding as unknown as Value,
      commitment: c,
    });
    const result = new Promise<Value>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        reject(new Error("result-unknown"));
      }, timeoutMs);
      this.pending.set(requestId, {
        resolve,
        reject,
        timer,
        commitment: c,
        binding: { ...this.binding },
      });
      void this.send
        .seal(Type.REQUEST, payload)
        .then((f) => this.transport.write(frame(f)))
        .catch((e) => this.close(e));
    });
    return { requestId, result };
  }
  /** 取消/查询/心跳均为 REQUEST 控制操作，由调用方提交目标 ID 与承诺；不自动重试支付。 */
  async close(reason: unknown = new Error("disconnected")): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.send.close();
    this.receive.close();
    this.reader.reset();
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(reason);
    }
    this.pending.clear();
    await this.transport.close();
  }
  private checkBinding(v: Value): void {
    const b = object(v, [
      "sessionId",
      "sessionEpoch",
      "connectionId",
      "deviceRunId",
    ]);
    if (Object.entries(this.binding).some(([k, x]) => b[k] !== x))
      fail("stale-session");
  }
}
