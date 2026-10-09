import { crc32 } from "../../src/frame.ts";
/** 仅测试：改变真实密文并重新算帧 CRC，让设备真正执行 GCM 拒绝路径。 */
export class FaultTransport {
  constructor(inner) {
    this.inner = inner;
    this.corrupt = false;
  }
  read() {
    return this.inner.read();
  }
  close() {
    return this.inner.close();
  }
  write(bytes) {
    let actual = bytes;
    if (this.corrupt && bytes[3] === 16) {
      this.corrupt = false;
      actual = bytes.slice();
      actual[11] ^= 1;
      new DataView(
        actual.buffer,
        actual.byteOffset,
        actual.byteLength,
      ).setUint32(
        actual.length - 4,
        crc32(actual.subarray(2, actual.length - 4)),
        true,
      );
    }
    return this.inner.write(actual);
  }
  corruptNextRequest() {
    this.corrupt = true;
  }
}
