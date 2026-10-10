import {commitment} from "./crypto.js";
import {secpIdentityVerifier} from "./bsv.js";
import { equal, fail, fixed } from "./bytes.js";
import { decode, encode, object, type Value } from "./cbor.js";

/** Public device recovery record. It is a commitment to progress, not a key
 * backup or authorization. Only the device's private migration controller may
 * advance it after the corresponding physical/storage action succeeds. */
export interface DeviceMigrationRecord {
  version: 1;
  id: string;
  walletGeneration: string;
  publicKey: Uint8Array;
  sourceHash: Uint8Array;
  policyHash: Uint8Array;
  direction: "to-hardware" | "to-software";
  phase: "staged" | "device-committed" | "host-committed" | "erasing" | "erased" | "complete";
  targetHash: Uint8Array | null;
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const fields = ["version", "id", "walletGeneration", "publicKey", "sourceHash", "policyHash", "direction", "phase", "targetHash"];
export function inspectDeviceMigration(value: unknown): DeviceMigrationRecord {
  const r = object(value as Value, fields);
  if (r.version !== 1 || typeof r.id !== "string" || !uuid.test(r.id)
    || typeof r.walletGeneration !== "string" || !uuid.test(r.walletGeneration)
    || (r.direction !== "to-hardware" && r.direction !== "to-software")
    || typeof r.phase !== "string" || !["staged", "device-committed", "host-committed", "erasing", "erased", "complete"].includes(r.phase)) fail("corrupt-migration");
  const pub = fixed(r.publicKey as Uint8Array, 33);
  if (pub[0] !== 2 && pub[0] !== 3) fail("corrupt-migration");
  const hasTarget = !["staged", "device-committed"].includes(r.phase);
  if (hasTarget !== (r.targetHash !== null)
    || (r.direction === "to-hardware" && ["erasing", "erased"].includes(r.phase))) fail("corrupt-migration");
  return {version: 1, id: r.id, walletGeneration: r.walletGeneration,
    publicKey: new Uint8Array(pub), sourceHash: new Uint8Array(fixed(r.sourceHash as Uint8Array, 32)),
    policyHash: new Uint8Array(fixed(r.policyHash as Uint8Array, 32)), direction: r.direction,
    phase: r.phase as DeviceMigrationRecord["phase"],
    targetHash: r.targetHash === null ? null : new Uint8Array(fixed(r.targetHash as Uint8Array, 32))};
}
export function encodeDeviceMigration(value: DeviceMigrationRecord): Uint8Array {
  return encode(inspectDeviceMigration(value) as unknown as Value, 1024);
}
export function decodeDeviceMigration(bytes: Uint8Array): DeviceMigrationRecord {
  return inspectDeviceMigration(decode(bytes, 1024));
}
/** The host must bind a public status reply to its durable journal before using
 * the phase. Receiving "complete" for another migration cannot activate a key. */
export function assertDeviceMigrationBinding(record: DeviceMigrationRecord,
  expected: Pick<DeviceMigrationRecord, "id" | "walletGeneration" | "publicKey" | "sourceHash" | "policyHash" | "direction">): void {
  const r = inspectDeviceMigration(record);
  if (r.id !== expected.id || r.walletGeneration !== expected.walletGeneration || r.direction !== expected.direction
    || !equal(r.publicKey, expected.publicKey) || !equal(r.sourceHash, expected.sourceHash) || !equal(r.policyHash, expected.policyHash)) fail("migration-conflict");
}

/** Semantic import proof: the freshly PIN-wrapped business key signs an exact
 * source identity/ledger/challenge tuple. A temporary USB key cannot substitute
 * its handshake signature, and a public phase alone is not proof of import. */
export async function migrationImportProofCommitment(record: DeviceMigrationRecord, challenge: Uint8Array): Promise<Uint8Array> {
  const r=inspectDeviceMigration(record);
  if(r.direction!=="to-hardware")fail("migration-conflict");
  return commitment("key-import-proof",1,{id:r.id,publicKey:r.publicKey,sourceHash:r.sourceHash,policyHash:r.policyHash,challenge:fixed(challenge,32)});
}
export async function verifyMigrationImportProof(record:DeviceMigrationRecord,challenge:Uint8Array,signature:Uint8Array):Promise<void>{
  const r=inspectDeviceMigration(record);
  if(!["device-committed","host-committed","complete"].includes(r.phase)
    ||!secpIdentityVerifier.verify(await migrationImportProofCommitment(r,challenge),signature,r.publicKey))fail("migration-key-proof-invalid");
}
