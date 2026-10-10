import { Reader, frame, MAX_PAYLOAD } from "./wire.mjs";
import { decode } from "../../src/cbor.ts";
import { FrameReader } from "../../src/frame.ts";
// 物理串口只有一个读者；数据帧不解密，控制帧仅操作测试 UI。没有伪造响应。
export class RocKeyTestLink {
  parser = new Reader();
  inboundVlp = new FrameReader();
  outboundVlp = new FrameReader();
  pending = new Map();
  next = 1;
  tail = Promise.resolve();
  stopped = false;
  constructor(transport) {
    this.transport = transport;
    this.readable = new ReadableStream({
      start: (c) => {
        this.output = c;
      },
    });
    this.writable = new WritableStream({ write: (b) => this.send(1, 0, b) });
    this.running = this.pump().catch((e) => this.fail(e));
  }
  async pump() {
    while (!this.stopped) {
      const b = await this.transport.read();
      if (b === null) throw Error("test-device-disconnected");
      // 仅保留 ESP panic 的地址/故障标签，不能记录原始串口密文或钱包数据。
      this.panicTail = (
        (this.panicTail ?? "") + new TextDecoder().decode(b)
      ).slice(-2048);
      const panic = this.panicTail.match(
        /Guru Meditation Error:[^\r\n]{0,160}|Backtrace: (?:0x[0-9a-f]+:0x[0-9a-f]+ ?)+|assert failed: [^\r\n]{0,160}/g,
      );
      if (panic) {
        console.info("[RocKey E2E] firmware panic: " + panic.join("; "));
        this.panicTail = "";
      }
      const dropped = this.parser.dropped;
      const received = this.parser.feed(b);
      if (this.parser.dropped !== dropped)
        console.info(
          "[RocKey E2E] USB outer-frame CRC/length failures=" +
            this.parser.dropped,
        );
      for (const f of received) {
        if (f.kind === 1) {
          for (const packet of this.inboundVlp.feed(f.payload))
            console.info(
              "[RocKey E2E] VLP rx type=" +
                packet.type +
                " seq=" +
                packet.seq +
                " size=" +
                packet.payload.length,
            );
          this.output.enqueue(f.payload);
        } else if (f.kind === 3) {
          const p = this.pending.get(f.id);
          if (p) {
            clearTimeout(p.timer);
            this.pending.delete(f.id);
            try {
              const value = decode(f.payload);
              if (value.error) throw Error(value.error);
              p.resolve(value);
            } catch (e) {
              p.reject(e);
            }
          }
        }
      }
    }
  }
  send(kind, id, bytes) {
    const frozen = bytes.slice();
    if (kind === 1)
      for (const packet of this.outboundVlp.feed(frozen))
        console.info(
          "[RocKey E2E] VLP tx type=" +
            packet.type +
            " seq=" +
            packet.seq +
            " size=" +
            packet.payload.length,
        );
    const job = this.tail.then(async () => {
      if (this.stopped) throw Error("test-link-closed");
      for (let at = 0; at < frozen.length; at += MAX_PAYLOAD)
        await this.transport.write(
          frame(kind, id, frozen.slice(at, at + MAX_PAYLOAD)),
        );
    });
    this.tail = job.catch(() => {});
    return job;
  }
  control(bytes, timeout = 20000) {
    if (this.stopped || this.pending.size >= 8)
      return Promise.reject(Error("test-link-unavailable"));
    if (this.next > 0xffffffff)
      return Promise.reject(Error("test-id-exhausted"));
    const id = this.next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(
          Error(
            "test-control-timeout: confirm product E2E firmware is installed",
          ),
        );
      }, timeout);
      this.pending.set(id, { resolve, reject, timer });
      void this.send(2, id, Uint8Array.from(bytes)).catch((e) => {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(e);
      });
    });
  }
  status() {
    return this.control([1]);
  }
  async press(button, ms = 220) {
    if (![0, 1, 2].includes(button) || ms < 60 || ms > 3500)
      throw Error("invalid-test-press");
    await this.control([2, button, 1, (ms + 100) & 255, (ms + 100) >> 8]);
    try {
      await new Promise((r) => setTimeout(r, ms));
    } finally {
      await this.control([2, button, 0, 0, 0]);
    }
    await new Promise((r) => setTimeout(r, 80));
  }
  fail(e) {
    if (this.stopped) return;
    this.stopped = true;
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(e);
    }
    this.pending.clear();
    try {
      this.output.error(e);
    } catch {}
    this.closing = this.transport.close().catch(() => {});
  }
  async close() {
    if (!this.stopped) {
      try {
        this.lastClosingStatus = await this.control([1], 1000);
        console.info(
          "[RocKey E2E] device before USB close: " +
            JSON.stringify(this.lastClosingStatus),
        );
      } catch (e) {
        console.info(
          "[RocKey E2E] device before USB close unavailable: " + e.message,
        );
      }
    }
    this.fail(Error("test-link-closed"));
    await Promise.all([this.running, this.closing]);
  }
  // 正式 Window→Worker 字节桥接收 SerialPortLike。串口已由外层打开，禁止二次打开。
  serialFacade() {
    return {
      readable: this.readable,
      writable: this.writable,
      open: async () => {},
      close: () => this.close(),
    };
  }
}
