import { equal, fail, fixed, u32 } from "./bytes.js";
export type RequestState =
  | "awaiting-user"
  | "executing"
  | "completed"
  | "denied"
  | "cancelled"
  | "unknown";
export interface RequestIdentity {
  id: number;
  sessionId: string;
  commitment: Uint8Array;
}
export interface RequestResult extends RequestIdentity {
  state: RequestState;
  payload: Uint8Array | null;
}
/** 单业务槽 + 一个最近结果 + 接受水位；结果淘汰绝不允许旧 ID 再执行。 */
export class RequestGate {
  private watermark = 0;
  private active: RequestResult | undefined;
  private recent: RequestResult | undefined;
  private closed = false;
  accept(r: RequestIdentity): RequestResult {
    if (this.closed) fail("disconnected");
    u32(r.id);
    if (
      r.id === 0 ||
      !r.sessionId ||
      fixed(r.commitment, 32).every((x) => x === 0)
    )
      fail("invalid-request");
    const known =
      this.active?.id === r.id
        ? this.active
        : this.recent?.id === r.id
          ? this.recent
          : undefined;
    if (known) {
      if (
        known.sessionId !== r.sessionId ||
        !equal(known.commitment, r.commitment)
      )
        fail("request-conflict");
      return this.copy(known);
    }
    if (r.id <= this.watermark) fail("replay");
    if (this.active) fail("busy");
    this.watermark = r.id;
    this.active = {
      ...r,
      commitment: r.commitment.slice(),
      state: "awaiting-user",
      payload: null,
    };
    return this.copy(this.active);
  }
  start(id: number): void {
    const r = this.current(id);
    if (r.state !== "awaiting-user") fail("invalid-state");
    r.state = "executing";
  }
  complete(id: number, payload: Uint8Array): RequestResult {
    const r = this.current(id);
    if (r.state !== "executing" || payload.length > 896) fail("invalid-state");
    r.state = "completed";
    r.payload = payload.slice();
    return this.finish(r);
  }
  cancel(id: number, commitment: Uint8Array): RequestResult {
    const r =
      this.active?.id === id
        ? this.active
        : this.recent?.id === id
          ? this.recent
          : undefined;
    if (!r) fail("result-unknown");
    if (!equal(fixed(commitment, 32), r.commitment)) fail("request-conflict");
    if (r.state === "awaiting-user") {
      r.state = "cancelled";
      return this.finish(r);
    }
    return this.copy(r);
  }
  deny(id: number): RequestResult {
    const r = this.current(id);
    if (r.state !== "awaiting-user") fail("invalid-state");
    r.state = "denied";
    return this.finish(r);
  }
  unknown(id: number): RequestResult {
    const r = this.current(id);
    r.state = "unknown";
    return this.finish(r);
  }
  query(
    id: number,
    sessionId: string,
    commitment: Uint8Array,
  ): RequestResult | null {
    const r =
      this.active?.id === id
        ? this.active
        : this.recent?.id === id
          ? this.recent
          : undefined;
    if (!r) return null;
    if (
      r.sessionId !== sessionId ||
      !equal(fixed(commitment, 32), r.commitment)
    )
      fail("request-conflict");
    return this.copy(r);
  }
  invalidate(): void {
    this.closed = true;
    this.active = undefined;
    this.recent =
      undefined; /* 不把清空水位当作同连接新请求；对象永久关闭，重连另建实例。 */
  }
  private current(id: number): RequestResult {
    if (this.closed) fail("disconnected");
    if (!this.active || this.active.id !== id) fail("invalid-request");
    return this.active;
  }
  private finish(r: RequestResult): RequestResult {
    this.recent = r;
    this.active = undefined;
    return this.copy(r);
  }
  private copy(r: RequestResult): RequestResult {
    return {
      ...r,
      commitment: r.commitment.slice(),
      payload: r.payload?.slice() ?? null,
    };
  }
}
