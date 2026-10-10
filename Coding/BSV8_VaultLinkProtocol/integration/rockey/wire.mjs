// RocKey 测试固件外层帧。独立于 VLP SDK 公共 API，不可用于正式设备。
export const MAX_PAYLOAD = 4096;
export function crc32(bytes) {
  let c = 0xffffffff;
  for (const x of bytes) {
    c ^= x;
    for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (c & 1 ? 0xedb88320 : 0);
  }
  return (c ^ 0xffffffff) >>> 0;
}
export function frame(kind, id, payload) {
  if (
    ![1, 2, 3].includes(kind) ||
    !Number.isInteger(id) ||
    id < 0 ||
    id > 0xffffffff ||
    payload.length > MAX_PAYLOAD
  )
    throw Error("invalid-test-frame");
  const b = new Uint8Array(payload.length + 15),
    d = new DataView(b.buffer);
  b.set([82, 75, 69, 84, kind]);
  d.setUint32(5, id, true);
  d.setUint16(9, payload.length, true);
  b.set(payload, 11);
  d.setUint32(b.length - 4, crc32(b.subarray(0, b.length - 4)), true);
  return b;
}
export class Reader {
  buffer = new Uint8Array(MAX_PAYLOAD + 15);
  used = 0;
  dropped = 0;
  shift(n) {
    this.buffer.copyWithin(0, n, this.used);
    this.used -= n;
  }
  feed(bytes) {
    const out = [];
    for (const x of bytes) {
      if (this.used === this.buffer.length) this.shift(1);
      this.buffer[this.used++] = x;
      while (this.used >= 4) {
        if (
          this.buffer[0] !== 82 ||
          this.buffer[1] !== 75 ||
          this.buffer[2] !== 69 ||
          this.buffer[3] !== 84
        ) {
          this.shift(1);
          continue;
        }
        if (this.used < 11) break;
        const d = new DataView(this.buffer.buffer),
          len = d.getUint16(9, true);
        if (len > MAX_PAYLOAD || ![1, 2, 3].includes(this.buffer[4])) {
          this.dropped++;
          this.shift(1);
          continue;
        }
        if (this.used < len + 15) break;
        if (
          d.getUint32(11 + len, true) !==
          crc32(this.buffer.subarray(0, 11 + len))
        ) {
          this.dropped++;
          this.shift(1);
          continue;
        }
        out.push({
          kind: this.buffer[4],
          id: d.getUint32(5, true),
          payload: this.buffer.slice(11, 11 + len),
        });
        this.shift(len + 15);
      }
    }
    return out;
  }
}
