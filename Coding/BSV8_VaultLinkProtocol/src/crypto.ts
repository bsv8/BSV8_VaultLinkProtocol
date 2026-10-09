import { be32, concat, equal, fail, fixed, MAX_U64, utf8 } from "./bytes.js";
import { encode, type Value } from "./cbor.js";
import { type Frame, MAX_FRAME_PAYLOAD, VERSION } from "./frame.js";
const raw = (b: Uint8Array): ArrayBuffer => b.slice().buffer as ArrayBuffer;
export const sha256 = async (b: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", raw(b)));
export const sha256d = async (b: Uint8Array): Promise<Uint8Array> =>
  sha256(await sha256(b));
export async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", raw(ikm), "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: raw(salt), info: raw(info) },
      key,
      length * 8,
    ),
  );
}
export async function ephemeral(): Promise<{
  privateKey: CryptoKey;
  publicKey: Uint8Array;
}> {
  const keys = (await crypto.subtle.generateKey({ name: "X25519" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  return {
    privateKey: keys.privateKey,
    publicKey: new Uint8Array(
      await crypto.subtle.exportKey("raw", keys.publicKey),
    ),
  };
}
export async function sharedSecret(
  privateKey: CryptoKey,
  publicKey: Uint8Array,
): Promise<Uint8Array> {
  const peer = await crypto.subtle.importKey(
    "raw",
    raw(fixed(publicKey, 32)),
    { name: "X25519" },
    false,
    [],
  );
  const secret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "X25519", public: peer },
      privateKey,
      256,
    ),
  );
  if (secret.every((x) => x === 0)) fail("invalid-peer");
  return secret;
}
/** v2 绑定完整 HELLO/ACK，包含连接 ID、所有能力/限额与公开状态，不延用旧未完整绑定的 transcript。 */
export async function transcript(
  hello: Value,
  ack: Value,
): Promise<Uint8Array> {
  return sha256(
    concat(utf8("vlp:handshake:v2\0"), encode({ hello, ack }, 2048)),
  );
}
export async function pairingCode(t: Uint8Array): Promise<string> {
  const h = await sha256(concat(utf8("vlp:link:pairing:v2"), fixed(t, 32)));
  return (((h[0]! << 16) | (h[1]! << 8) | h[2]!) % 1000000)
    .toString()
    .padStart(6, "0");
}
export interface DirectionKeys {
  c2sKey: Uint8Array;
  c2sBaseNonce: Uint8Array;
  s2cKey: Uint8Array;
  s2cBaseNonce: Uint8Array;
}
export async function deriveKeys(
  shared: Uint8Array,
  t: Uint8Array,
): Promise<DirectionKeys> {
  fixed(shared, 32);
  fixed(t, 32);
  return {
    c2sKey: await hkdf(shared, t, utf8("vlp:link:c2s:key:v2"), 32),
    c2sBaseNonce: await hkdf(shared, t, utf8("vlp:link:c2s:nonce:v2"), 12),
    s2cKey: await hkdf(shared, t, utf8("vlp:link:s2c:key:v2"), 32),
    s2cBaseNonce: await hkdf(shared, t, utf8("vlp:link:s2c:nonce:v2"), 12),
  };
}
export function nonce(base: Uint8Array, count: bigint): Uint8Array {
  fixed(base, 12);
  if (count < 0n || count >= MAX_U64) fail("counter-exhausted");
  const b = base.slice();
  let c = count;
  for (let i = 11; i >= 0; i--) {
    c += BigInt(b[i]!);
    b[i] = Number(c & 255n);
    c >>= 8n;
  }
  return b;
}
export async function commitment(
  profile: string,
  version: number,
  core: Value,
): Promise<Uint8Array> {
  if (
    !/^[a-z][a-z0-9-]{0,30}$/.test(profile) ||
    !Number.isInteger(version) ||
    version < 1 ||
    version > 255
  )
    fail("invalid-profile");
  return sha256d(
    concat(
      utf8("vlp:commit:v2\0" + profile + "\0"),
      Uint8Array.of(version),
      encode(core),
    ),
  );
}
export interface RecordContext {
  deviceRunId: number;
  connectionId: number;
}
/** 每个方向独立对象。所有异步运算串行化；并行调用不能复用 nonce。失败即销毁连接材料。 */
export class RecordCipher {
  private key: CryptoKey | undefined;
  private base: Uint8Array;
  private counter = 0n;
  private seq = 0;
  private closed = false;
  private tail: Promise<unknown> = Promise.resolve();
  private constructor(
    key: CryptoKey,
    base: Uint8Array,
    private ctx: RecordContext,
  ) {
    this.key = key;
    this.base = base.slice();
  }
  static async create(
    key: Uint8Array,
    base: Uint8Array,
    ctx: RecordContext,
  ): Promise<RecordCipher> {
    fixed(key, 32);
    fixed(base, 12);
    be32(ctx.deviceRunId);
    be32(ctx.connectionId);
    return new RecordCipher(
      await crypto.subtle.importKey("raw", raw(key), "AES-GCM", false, [
        "encrypt",
        "decrypt",
      ]),
      base,
      ctx,
    );
  }
  close(): void {
    this.closed = true;
    this.key = undefined;
    this.base.fill(0);
  }
  private serial<T>(f: () => Promise<T>): Promise<T> {
    const p = this.tail.then(f);
    this.tail = p.catch(() => {});
    return p;
  }
  private aad(type: number, seq: number): Uint8Array {
    return concat(
      Uint8Array.of(VERSION, type, 0),
      be32(seq),
      be32(this.ctx.deviceRunId),
      be32(this.ctx.connectionId),
    );
  }
  seal(type: number, plain: Uint8Array): Promise<Frame> {
    const copy = plain.slice();
    return this.serial(async () => {
      try {
        if (this.closed || !this.key) fail("disconnected");
        if (
          type < 3 ||
          ![3, 4, 5, 6, 16, 17, 18].includes(type) ||
          copy.length > 896 ||
          this.seq === 0xffffffff
        )
          fail("invalid-record");
        const seq = this.seq + 1;
        const payload = new Uint8Array(
          await crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv: raw(nonce(this.base, this.counter)),
              additionalData: raw(this.aad(type, seq)),
              tagLength: 128,
            },
            this.key,
            raw(copy),
          ),
        );
        this.seq = seq;
        this.counter++;
        return { type, seq, payload };
      } catch (e) {
        this.close();
        throw e;
      } finally {
        copy.fill(0);
      }
    });
  }
  open(f: Frame): Promise<Uint8Array> {
    const payload = f.payload.slice();
    return this.serial(async () => {
      try {
        if (this.closed || !this.key) fail("disconnected");
        if (
          ![3, 4, 5, 6, 16, 17, 18].includes(f.type) ||
          f.seq !== this.seq + 1 ||
          payload.length < 16 ||
          payload.length > MAX_FRAME_PAYLOAD
        )
          fail("replay-or-gap");
        const plain = new Uint8Array(
          await crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: raw(nonce(this.base, this.counter)),
              additionalData: raw(this.aad(f.type, f.seq)),
              tagLength: 128,
            },
            this.key,
            raw(payload),
          ),
        );
        if (plain.length > 896) fail("message-too-large");
        this.seq = f.seq;
        this.counter++;
        return plain;
      } catch (e) {
        this.close();
        throw e;
      }
    });
  }
}
export async function verifyCommitment(
  expected: Uint8Array,
  profile: string,
  version: number,
  core: Value,
): Promise<void> {
  if (!equal(fixed(expected, 32), await commitment(profile, version, core)))
    fail("invalid-commitment");
}
