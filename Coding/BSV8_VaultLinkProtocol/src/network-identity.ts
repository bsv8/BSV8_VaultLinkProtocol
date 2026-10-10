import type { OperationHandler } from "./device.js";
import { concat, fail, utf8 } from "./bytes.js";
import { object, type Value } from "./cbor.js";
import { sha256 } from "./crypto.js";
export type NetworkIdentityKind = "noise" | "peer-record";
export interface NetworkIdentityReview { kind:NetworkIdentityKind; digest:Uint8Array; payload:Uint8Array; sequence?:string; }
function varint(value:bigint):Uint8Array { const bytes:number[]=[];do{let byte=Number(value&127n);value>>=7n;bytes.push(byte|(value?128:0));}while(value);return Uint8Array.from(bytes); }
/** Reconstruct only the existing address-free libp2p identity record from our own key. */
export async function inspectNetworkIdentity(kind:NetworkIdentityKind,body:Value,ownPublicKey:Uint8Array):Promise<NetworkIdentityReview> {
  if(ownPublicKey.length!==33)fail("wrong-key");
  let payload:Uint8Array,sequence:string|undefined;
  if(kind==="noise") {
    const b=object(body,["staticKey"]);if(!(b.staticKey instanceof Uint8Array)||b.staticKey.length!==32)fail("invalid-noise-key");
    payload=concat(utf8("noise-libp2p-static-key:"),b.staticKey);
  }else if(kind==="peer-record") {
    const b=object(body,["sequence"]);if(typeof b.sequence!=="string"||!/^(0|[1-9][0-9]{0,19})$/.test(b.sequence))fail("invalid-sequence");
    sequence=b.sequence;const seq=BigInt(sequence);if(seq>0xffffffffffffffffn)fail("invalid-sequence");
    // identity multihash of protobuf PublicKey {Type:secp256k1,Data:compressed SEC1}.
    const peerId=concat(Uint8Array.of(0,37,8,2,18,33),ownPublicKey);
    const record=concat(Uint8Array.of(10,peerId.length),peerId,seq===0n?new Uint8Array():concat(Uint8Array.of(16),varint(seq)));
    const domain=utf8("libp2p-peer-record");payload=concat(varint(BigInt(domain.length)),domain,Uint8Array.of(2,3,1),varint(BigInt(record.length)),record);
  }else fail("unsupported");
  return {kind,payload,digest:await sha256(payload),...(sequence!==undefined?{sequence}:{})};
}

/** Semantic adapter for SDK DeviceServer; authorization stays in the device. */
export class NetworkIdentityOperation implements OperationHandler {
 readonly profile:string;readonly version=1;
 constructor(private key:import("./bsv.js").DeviceIdentityKey,private kind:NetworkIdentityKind,
   private confirm:(review:NetworkIdentityReview,signal:AbortSignal)=>Promise<boolean>){this.profile=`libp2p-identity-${kind}`;}
 async verify(body:Value):Promise<Value>{const frozen=structuredClone(body);await inspectNetworkIdentity(this.kind,frozen,this.key.publicKey());return frozen;}
 async authorize(core:Value,signal:AbortSignal):Promise<boolean>{return this.confirm(await inspectNetworkIdentity(this.kind,core,this.key.publicKey()),signal);}
 async execute(core:Value,signal:AbortSignal):Promise<Value>{return {publicKey:this.key.publicKey(),signature:await this.key.signNetworkIdentity(this.kind,core,signal,async()=>true)};}
}
