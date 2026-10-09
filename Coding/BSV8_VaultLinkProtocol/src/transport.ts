import { fail } from "./bytes.js";
export interface Transport {
  read(): Promise<Uint8Array | null>;
  write(bytes: Uint8Array): Promise<void>;
  close(): Promise<void>;
}
export interface SerialPortLike {
  readable: ReadableStream<Uint8Array> | null;
  writable: WritableStream<Uint8Array> | null;
  open(options: { baudRate: number }): Promise<void>;
  close(): Promise<void>;
}
/** 串口许可由 Window 的用户手势取得，再把 port 交给适配器；核心不访问 navigator 或 Coordinator。 */
export class WebSerialTransport implements Transport {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private stopped = false;
  private constructor(private port: SerialPortLike) {
    if (!port.readable || !port.writable) fail("port-unavailable");
    this.reader = port.readable.getReader();
    this.writer = port.writable.getWriter();
  }
  static async open(
    port: SerialPortLike,
    baudRate = 115200,
  ): Promise<WebSerialTransport> {
    await port.open({ baudRate });
    return new WebSerialTransport(port);
  }
  async read(): Promise<Uint8Array | null> {
    if (this.stopped) return null;
    const r = await this.reader.read();
    return r.done ? null : r.value;
  }
  async write(bytes: Uint8Array): Promise<void> {
    if (this.stopped) fail("disconnected");
    await this.writer.write(bytes.slice());
  }
  async close(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    // 拔插时不能等待未完成写入正常排空。读取消/写中止都执行，再释放句柄。
    await Promise.allSettled([this.reader.cancel(), this.writer.abort()]);
    this.reader.releaseLock();
    this.writer.releaseLock();
    await this.port.close();
  }
}
