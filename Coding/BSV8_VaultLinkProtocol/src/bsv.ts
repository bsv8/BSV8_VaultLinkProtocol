import { secp256k1 } from "@noble/curves/secp256k1";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { sha256 as hash256 } from "@noble/hashes/sha256";
import { addMoney, concat, equal, fail, fixed, money, u32 } from "./bytes.js";
import { sha256d } from "./crypto.js";
import { possessionDigest } from "./handshake.js";
import { externalOutputAmount } from "./payment.js";
export interface TxInput {
  txid: Uint8Array;
  vout: number;
  script: Uint8Array;
  sequence: number;
}
export interface TxOutput {
  satoshis: bigint;
  script: Uint8Array;
}
export interface Transaction {
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
}
export interface PrevoutEvidence {
  transaction: Uint8Array;
}
export interface BsvReview {
  publicKey: Uint8Array;
  externalOutputs: TxOutput[];
  change: bigint;
  fee: bigint;
  amount: bigint;
  digest: Uint8Array;
  inputIndex: number;
}
const le32 = (x: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, u32(x), true);
  return b;
};
const le64 = (x: bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, money(x), true);
  return b;
};
function compact(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 65535) fail("transaction-limit");
  if (n < 253) return Uint8Array.of(n);
  return Uint8Array.of(253, n & 255, n >>> 8);
}
export function p2pkhScript(pub: Uint8Array): Uint8Array {
  fixed(pub, 33);
  secp256k1.ProjectivePoint.fromHex(pub);
  return concat(
    Uint8Array.of(0x76, 0xa9, 0x14),
    ripemd160(hash256(pub)),
    Uint8Array.of(0x88, 0xac),
  );
}
function p2pkh(script: Uint8Array): boolean {
  return (
    script.length === 25 &&
    script[0] === 0x76 &&
    script[1] === 0xa9 &&
    script[2] === 0x14 &&
    script[23] === 0x88 &&
    script[24] === 0xac
  );
}
/** 不接受 witness/非最短 CompactSize、超大前序或未知脚本；前序真实性靠 txid/outpoint 字节绑定，不声称链上状态。 */
export function parseTransaction(
  raw: Uint8Array,
  maxBytes = 8192,
): Transaction {
  if (raw.length > maxBytes) fail("transaction-limit");
  let at = 0;
  const take = (n: number) => {
    if (n < 0 || at + n > raw.length) fail("truncated-transaction");
    const b = raw.slice(at, at + n);
    at += n;
    return b;
  };
  const read32 = () => new DataView(take(4).buffer).getUint32(0, true);
  const read64 = () => new DataView(take(8).buffer).getBigUint64(0, true);
  const count = () => {
    const n = take(1)[0]!;
    if (n < 253) return n;
    if (n !== 253) fail("transaction-limit");
    const b = take(2),
      x = b[0]! | (b[1]! << 8);
    if (x < 253) fail("non-shortest");
    return x;
  };
  const version = read32(),
    ni = count();
  if (ni < 1 || ni > 128) fail("transaction-limit");
  const inputs: TxInput[] = [];
  for (let i = 0; i < ni; i++) {
    const txid = take(32),
      vout = read32(),
      len = count();
    if (len > 1024) fail("transaction-limit");
    inputs.push({ txid, vout, script: take(len), sequence: read32() });
  }
  const no = count();
  if (no < 1 || no > 128) fail("transaction-limit");
  const outputs: TxOutput[] = [];
  for (let i = 0; i < no; i++) {
    const satoshis = read64(),
      len = count();
    if (len > 1024) fail("transaction-limit");
    outputs.push({ satoshis, script: take(len) });
  }
  const locktime = read32();
  if (at !== raw.length) fail("trailing-transaction");
  return { version, inputs, outputs, locktime };
}
function outputBytes(o: TxOutput): Uint8Array {
  return concat(le64(o.satoshis), compact(o.script.length), o.script);
}
export function serializeTransaction(tx: Transaction): Uint8Array {
  return concat(
    le32(tx.version),
    compact(tx.inputs.length),
    ...tx.inputs.map((i) =>
      concat(
        fixed(i.txid, 32),
        le32(i.vout),
        compact(i.script.length),
        i.script,
        le32(i.sequence),
      ),
    ),
    compact(tx.outputs.length),
    ...tx.outputs.map(outputBytes),
    le32(tx.locktime),
  );
}
/** 仅计算规范交易摘要；不产生签名，也不代替完整前序输出核验。 */
export async function p2pkhSighash(
  tx: Transaction,
  inputIndex: number,
  prev: TxOutput,
): Promise<Uint8Array> {
  if (
    !Number.isInteger(inputIndex) ||
    inputIndex < 0 ||
    inputIndex >= tx.inputs.length ||
    !p2pkh(prev.script)
  )
    fail("invalid-prevout");
  money(prev.satoshis);
  const hashPrevouts = await sha256d(
      concat(...tx.inputs.map((i) => concat(i.txid, le32(i.vout)))),
    ),
    hashSequence = await sha256d(
      concat(...tx.inputs.map((i) => le32(i.sequence))),
    ),
    hashOutputs = await sha256d(concat(...tx.outputs.map(outputBytes)));
  const input = tx.inputs[inputIndex]!;
  return sha256d(
    concat(
      le32(tx.version),
      hashPrevouts,
      hashSequence,
      input.txid,
      le32(input.vout),
      compact(prev.script.length),
      prev.script,
      le64(prev.satoshis),
      le32(input.sequence),
      hashOutputs,
      le32(tx.locktime),
      le32(0x41),
    ),
  );
}
export async function inspectP2pkh(
  raw: Uint8Array,
  evidence: PrevoutEvidence[],
  publicKey: Uint8Array,
  inputIndex: number,
): Promise<BsvReview> {
  const tx = parseTransaction(raw, 640);
  if (
    tx.inputs.length > 4 ||
    tx.outputs.length > 6 ||
    evidence.length !== tx.inputs.length ||
    !Number.isInteger(inputIndex) ||
    inputIndex < 0 ||
    inputIndex >= tx.inputs.length
  )
    fail("unsupported");
  const own = p2pkhScript(publicKey);
  let inputs = 0n;
  const prevouts: TxOutput[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < tx.inputs.length; i++) {
    const input = tx.inputs[i]!;
    if (input.script.length !== 0) fail("already-signed");
    const prior = parseTransaction(evidence[i]!.transaction);
    const txid = await sha256d(evidence[i]!.transaction);
    if (!equal(txid, input.txid) || input.vout >= prior.outputs.length)
      fail("invalid-prevout");
    const ref = Array.from(input.txid).join(",") + ":" + input.vout;
    if (seen.has(ref)) fail("duplicate-input");
    seen.add(ref);
    const prev = prior.outputs[input.vout]!;
    if (!equal(prev.script, own)) fail("wrong-key");
    inputs = addMoney(inputs, prev.satoshis);
    prevouts.push(prev);
  }
  let outputs = 0n,
    change = 0n;
  const external: TxOutput[] = [];
  for (const o of tx.outputs) {
    if (!p2pkh(o.script)) fail("unsupported-script");
    outputs = addMoney(outputs, o.satoshis);
    if (equal(o.script, own)) change = addMoney(change, o.satoshis);
    else external.push({ ...o, script: o.script.slice() });
  }
  if (outputs > inputs) fail("negative-fee");
  const digest = await p2pkhSighash(tx, inputIndex, prevouts[inputIndex]!);
  return {
    publicKey: publicKey.slice(),
    externalOutputs: external,
    change,
    fee: inputs - outputs,
    amount: externalOutputAmount(
      tx.outputs.map((o) => ({
        amount: o.satoshis,
        owned: equal(o.script, own),
      })),
    ),
    digest,
    inputIndex,
  };
}
/** 设备内部 KeyProvider：只签已经重新解析的 P2PKH 或域隔离持有权，普通 SDK 无 signHash/getPrivateKey。 */
export class DeviceIdentityKey {
  private key: Uint8Array;
  private closed = false;
  constructor(privateKey: Uint8Array) {
    fixed(privateKey, 32);
    if (!secp256k1.utils.isValidPrivateKey(privateKey)) fail("invalid-key");
    this.key = privateKey.slice();
  }
  publicKey(): Uint8Array {
    if (this.closed) fail("locked");
    return secp256k1.getPublicKey(this.key, true);
  }
  async signP2pkh(
    raw: Uint8Array,
    evidence: PrevoutEvidence[],
    inputIndex: number,
    authorize: (review: BsvReview) => Promise<boolean>,
    signal?: AbortSignal,
  ): Promise<{ review: BsvReview; signature: Uint8Array }> {
    const review = await inspectP2pkh(
      raw,
      evidence,
      this.publicKey(),
      inputIndex,
    );
    const frozen = review.digest.slice();
    if (!(await authorize(structuredClone(review)))) fail("denied");
    if (this.closed) fail("locked");
    if (signal?.aborted) fail("revoked");
    const signature = concat(
      secp256k1
        .sign(frozen, this.key, { prehash: false, lowS: true })
        .toDERRawBytes(),
      Uint8Array.of(0x41),
    );
    return { review, signature };
  }
  async signAllP2pkh(
    raw: Uint8Array,
    evidence: PrevoutEvidence[],
    signal: AbortSignal,
    beforeSign: () => Promise<void>,
  ): Promise<Uint8Array[]> {
    const tx = raw.slice(),
      prev = evidence.map((e) => ({ transaction: e.transaction.slice() })),
      count = parseTransaction(tx, 640).inputs.length;
    const reviews: BsvReview[] = [];
    for (let i = 0; i < count; i++)
      reviews.push(await inspectP2pkh(tx, prev, this.publicKey(), i));
    await beforeSign();
    if (this.closed) fail("locked");
    if (signal.aborted) fail("revoked");
    return reviews.map((r) =>
      concat(
        secp256k1
          .sign(r.digest, this.key, { prehash: false, lowS: true })
          .toDERRawBytes(),
        Uint8Array.of(0x41),
      ),
    );
  }
  async provePossession(
    transcript: Uint8Array,
    sessionId: number,
    challenge: Uint8Array,
  ): Promise<Uint8Array> {
    const digest = await possessionDigest(
      transcript,
      this.publicKey(),
      sessionId,
      challenge,
    );
    if (this.closed) fail("locked");
    return secp256k1
      .sign(digest, this.key, { prehash: false, lowS: true })
      .toDERRawBytes();
  }
  close(): void {
    this.closed = true;
    this.key.fill(0);
  }
}
export const secpIdentityVerifier = {
  verify: (
    digest: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): boolean => {
    try {
      return secp256k1.verify(
        signature,
        fixed(digest, 32),
        fixed(publicKey, 33),
        { prehash: false, lowS: true },
      );
    } catch {
      return false;
    }
  },
};
