import { equal, fail, fixed, u32 } from "./bytes.js";
import { decode, encode, object, type Value } from "./cbor.js";
import { FrameReader, frame, Type, type Frame } from "./frame.js";
import {
  DeviceHandshake,
  HostHandshake,
  type Generations,
  type IdentityVerifier,
  type PairedKeys,
  verifyPossession,
} from "./handshake.js";
import { type Transport } from "./transport.js";
import { type Binding, ProtocolClient } from "./client.js";
export interface DeviceKey {
  publicKey(): Uint8Array;
  provePossession(
    transcript: Uint8Array,
    sessionId: number,
    challenge: Uint8Array,
  ): Promise<Uint8Array>;
}
/** 真实字节管道，保留合并读取的多帧；握手/业务共用，避免在阶段切换时丢掉尾帧。 */
export class PacketLink {
  private reader = new FrameReader();
  private queue: Frame[] = [];
  private reading = false;
  constructor(readonly transport: Transport) {}
  async read(timeoutMs = 60000): Promise<Frame> {
    if (this.reading) fail("concurrent-read");
    this.reading = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        this.readNext(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            void this.transport.close();
            reject(new Error("link-timeout"));
          }, timeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
      this.reading = false;
    }
  }
  private async readNext(): Promise<Frame> {
    while (!this.queue.length) {
      const b = await this.transport.read();
      if (b === null) fail("disconnected");
      this.queue.push(...this.reader.feed(b));
    }
    return this.queue.shift()!;
  }
  async send(f: Frame): Promise<void> {
    await this.transport.write(frame(f));
  }
  /** Client 专用读取视图：把已缓冲尾帧重新编码，之后沿用同一字节管道。 */
  clientTransport(): Transport {
    return {
      read: async () => frame(await this.read(8000)),
      write: (b) => this.transport.write(b),
      close: () => this.transport.close(),
    };
  }
}
export interface ReadySession {
  link: PacketLink;
  keys: PairedKeys;
  binding: Binding;
}
export async function connectHost(
  transport: Transport,
  generations: Generations,
  expectedPublicKey: Uint8Array,
  verifier: IdentityVerifier,
  confirmPairing: (code: string) => Promise<boolean>,
  capabilities: number[] = [0x221],
): Promise<ProtocolClient> {
  const link = new PacketLink(transport),
    h = new HostHandshake();
  let keys: PairedKeys | undefined;
  try {
    await link.send({
      type: Type.HELLO,
      seq: 0,
      payload: encode(
        (await h.begin(generations, capabilities)) as unknown as Value,
      ),
    });
    const ackFrame = await link.read();
    if (ackFrame.type !== Type.HELLO_ACK || ackFrame.seq !== 0)
      fail("bad-hello");
    const ack = decode(ackFrame.payload);
    keys = await h.acceptAck(ack, expectedPublicKey);
    if (!(await confirmPairing(keys.pairingCode))) fail("pairing-denied");
    await link.send(
      await keys.send.seal(
        Type.PAIR_CONFIRM,
        encode({ code: keys.pairingCode }),
      ),
    );
    let f = await link.read();
    if (f.type !== Type.PAIR_OK) fail("bad-pair");
    const paired = object(decode(await keys.receive.open(f)), ["paired"]);
    if (paired.paired !== true) fail("pairing-denied");
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    await link.send(
      await keys.send.seal(Type.POSSESSION_PROVE, encode({ challenge })),
    );
    f = await link.read();
    if (f.type !== Type.POSSESSION_OK) fail("bad-proof");
    const proof = object(decode(await keys.receive.open(f)), [
      "challenge",
      "publicKey",
      "sessionId",
      "sessionEpoch",
      "signature",
    ]);
    if (
      !(proof.publicKey instanceof Uint8Array) ||
      !equal(proof.publicKey, expectedPublicKey) ||
      !(proof.challenge instanceof Uint8Array) ||
      !equal(proof.challenge, challenge) ||
      typeof proof.sessionId !== "number" ||
      proof.sessionEpoch !== 1 ||
      !(proof.signature instanceof Uint8Array)
    )
      fail("bad-proof");
    await verifyPossession(
      verifier,
      keys.transcript,
      expectedPublicKey,
      proof.sessionId,
      challenge,
      proof.signature,
    );
    const a = ack as Record<string, Value>;
    const binding: Binding = {
      sessionId: String(proof.sessionId),
      sessionEpoch: u32(proof.sessionEpoch),
      connectionId: a.connectionId as number,
      deviceRunId: a.deviceRunId as number,
    };
    return new ProtocolClient(
      link.clientTransport(),
      keys.send,
      keys.receive,
      binding,
    );
  } catch (e) {
    keys?.send.close();
    keys?.receive.close();
    await transport.close();
    throw e;
  }
}
export async function acceptDevice(
  transport: Transport,
  key: DeviceKey,
  deviceRunId: number,
  connectionId: number,
  confirmPairing: (code: string) => Promise<boolean>,
  capabilities: number[] = [0x221],
): Promise<ReadySession> {
  const link = new PacketLink(transport);
  let keys: PairedKeys | undefined;
  try {
    const f = await link.read();
    if (f.type !== Type.HELLO || f.seq !== 0) fail("bad-hello");
    const result = await new DeviceHandshake().acceptHello(
      decode(f.payload),
      key.publicKey(),
      deviceRunId,
      connectionId,
      capabilities,
    );
    keys = result.keys;
    await link.send({
      type: Type.HELLO_ACK,
      seq: 0,
      payload: encode(result.ack as unknown as Value),
    });
    if (!(await confirmPairing(keys.pairingCode))) fail("pairing-denied");
    const pairFrame = await link.read();
    if (pairFrame.type !== Type.PAIR_CONFIRM) fail("bad-pair");
    const pair = object(decode(await keys.receive.open(pairFrame)), ["code"]);
    if (pair.code !== keys.pairingCode) fail("bad-pair");
    await link.send(
      await keys.send.seal(Type.PAIR_OK, encode({ paired: true })),
    );
    const proofFrame = await link.read();
    if (proofFrame.type !== Type.POSSESSION_PROVE) fail("bad-proof");
    const proof = object(decode(await keys.receive.open(proofFrame)), [
      "challenge",
    ]);
    if (!(proof.challenge instanceof Uint8Array)) fail("bad-proof");
    fixed(proof.challenge, 32);
    const random = crypto.getRandomValues(new Uint32Array(1))[0]!;
    const sessionId = random || 1;
    const signature = await key.provePossession(
      keys.transcript,
      sessionId,
      proof.challenge,
    );
    await link.send(
      await keys.send.seal(
        Type.POSSESSION_OK,
        encode({
          challenge: proof.challenge,
          publicKey: key.publicKey(),
          sessionId,
          sessionEpoch: 1,
          signature,
        }),
      ),
    );
    return {
      link,
      keys,
      binding: {
        sessionId: String(sessionId),
        sessionEpoch: 1,
        connectionId,
        deviceRunId,
      },
    };
  } catch (e) {
    keys?.send.close();
    keys?.receive.close();
    await transport.close();
    throw e;
  }
}
