import { concat, equal, fail, fixed, utf8, be32 } from "./bytes.js";
import { type Value, object, encode } from "./cbor.js";
import {
  deriveKeys,
  ephemeral,
  pairingCode,
  RecordCipher,
  sha256d,
  sharedSecret,
  transcript,
} from "./crypto.js";
import { VERSION } from "./frame.js";
export interface Generations {
  walletGeneration: number;
  backendGeneration: number;
  hostRunGeneration: number;
}
export interface Hello extends Generations {
  hostEph: Uint8Array;
  hostNonce: Uint8Array;
  protocolVersion: number;
  capabilities: number[];
}
export interface Ack {
  deviceEph: Uint8Array;
  deviceNonce: Uint8Array;
  publicKey: Uint8Array;
  deviceRunId: number;
  connectionId: number;
  protocolVersion: number;
  capabilities: number[];
}
export interface PairedKeys {
  send: RecordCipher;
  receive: RecordCipher;
  pairingCode: string;
  transcript: Uint8Array;
}
function nonzero(n: number): number {
  be32(n);
  if (n === 0) fail("invalid-generation");
  return n;
}
function caps(v: Value): number[] {
  if (!Array.isArray(v) || v.length > 32) fail("invalid-capabilities");
  const list = v.map((x) => {
    if (typeof x !== "number") fail("invalid-capabilities");
    return nonzero(x);
  });
  if (new Set(list).size !== list.length) fail("invalid-capabilities");
  return list;
}
export function parseHello(v: Value): Hello {
  const x = object(v, [
    "hostEph",
    "hostNonce",
    "protocolVersion",
    "capabilities",
    "walletGeneration",
    "backendGeneration",
    "hostRunGeneration",
  ]);
  if (x.protocolVersion !== VERSION) fail("version-mismatch");
  const h = x as unknown as Hello;
  fixed(h.hostEph, 32);
  fixed(h.hostNonce, 32);
  nonzero(h.walletGeneration);
  nonzero(h.backendGeneration);
  nonzero(h.hostRunGeneration);
  caps(x.capabilities!);
  return h;
}
export function parseAck(v: Value): Ack {
  const x = object(v, [
    "deviceEph",
    "deviceNonce",
    "publicKey",
    "deviceRunId",
    "connectionId",
    "protocolVersion",
    "capabilities",
  ]);
  if (x.protocolVersion !== VERSION) fail("version-mismatch");
  const a = x as unknown as Ack;
  fixed(a.deviceEph, 32);
  fixed(a.deviceNonce, 32);
  fixed(a.publicKey, 33);
  if (a.publicKey[0] !== 2 && a.publicKey[0] !== 3) fail("invalid-key");
  nonzero(a.deviceRunId);
  nonzero(a.connectionId);
  caps(x.capabilities!);
  return a;
}
const val = (v: Hello | Ack): Value => v as unknown as Value;
async function keys(
  role: "host" | "device",
  priv: CryptoKey,
  h: Hello,
  a: Ack,
): Promise<PairedKeys> {
  const t = await transcript(val(h), val(a));
  const shared = await sharedSecret(
    priv,
    role === "host" ? a.deviceEph : h.hostEph,
  );
  try {
    const k = await deriveKeys(shared, t);
    const ctx = { deviceRunId: a.deviceRunId, connectionId: a.connectionId };
    try {
      return {
        send: await RecordCipher.create(
          role === "host" ? k.c2sKey : k.s2cKey,
          role === "host" ? k.c2sBaseNonce : k.s2cBaseNonce,
          ctx,
        ),
        receive: await RecordCipher.create(
          role === "host" ? k.s2cKey : k.c2sKey,
          role === "host" ? k.s2cBaseNonce : k.c2sBaseNonce,
          ctx,
        ),
        pairingCode: await pairingCode(t),
        transcript: t,
      };
    } finally {
      Object.values(k).forEach((x) => x.fill(0));
    }
  } finally {
    shared.fill(0);
  }
}
/** 配对码必须由两端用户核对。acceptAck 仅派生材料，不代表实体配对或身份验证已经完成。 */
export class HostHandshake {
  private priv: CryptoKey | undefined;
  private hello: Hello | undefined;
  private consumed = false;
  async begin(g: Generations, capabilities: number[]): Promise<Hello> {
    if (this.hello) fail("invalid-state");
    const e = await ephemeral();
    this.priv = e.privateKey;
    this.hello = {
      ...g,
      capabilities: [...capabilities],
      hostEph: e.publicKey,
      hostNonce: crypto.getRandomValues(new Uint8Array(32)),
      protocolVersion: VERSION,
    };
    parseHello(val(this.hello));
    return structuredClone(this.hello);
  }
  async acceptAck(
    value: Value,
    expectedPublicKey: Uint8Array,
  ): Promise<PairedKeys> {
    if (!this.priv || !this.hello || this.consumed) fail("invalid-state");
    this.consumed = true;
    const priv = this.priv;
    this.priv = undefined;
    const a = parseAck(value);
    if (!equal(a.publicKey, fixed(expectedPublicKey, 33))) fail("wrong-key");
    return keys("host", priv, this.hello, a);
  }
}
export class DeviceHandshake {
  private started = false;
  async acceptHello(
    value: Value,
    publicKey: Uint8Array,
    deviceRunId: number,
    connectionId: number,
    capabilities: number[],
  ): Promise<{ ack: Ack; keys: PairedKeys }> {
    if (this.started) fail("invalid-state");
    this.started = true;
    const h = parseHello(value);
    const e = await ephemeral();
    const ack: Ack = {
      deviceEph: e.publicKey,
      deviceNonce: crypto.getRandomValues(new Uint8Array(32)),
      publicKey: fixed(publicKey, 33).slice(),
      deviceRunId,
      connectionId,
      capabilities: [...capabilities],
      protocolVersion: VERSION,
    };
    parseAck(val(ack));
    return { ack, keys: await keys("device", e.privateKey, h, ack) };
  }
}
export async function possessionDigest(
  t: Uint8Array,
  publicKey: Uint8Array,
  sessionId: number,
  challenge: Uint8Array,
): Promise<Uint8Array> {
  return sha256d(
    concat(
      utf8("vlp:possession:v2\0"),
      fixed(t, 32),
      fixed(publicKey, 33),
      be32(nonzero(sessionId)),
      fixed(challenge, 32),
    ),
  );
}
export interface IdentityVerifier {
  verify(
    digest: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): boolean;
}
/** 只验证受限持有权声明；不存在通用业务 SIGN_HASH 出口。 */
export async function verifyPossession(
  verifier: IdentityVerifier,
  t: Uint8Array,
  expected: Uint8Array,
  sessionId: number,
  challenge: Uint8Array,
  signature: Uint8Array,
): Promise<void> {
  const digest = await possessionDigest(t, expected, sessionId, challenge);
  if (!verifier.verify(digest, signature, expected)) fail("wrong-key");
}
export const handshakeEncoding = (value: Hello | Ack): Uint8Array =>
  encode(val(value));
