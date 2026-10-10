import { fail, unhex } from "./bytes.js";
import { object, type Value } from "./cbor.js";
export interface LocalSecretV3 {
  version: 3;
  keySource: "active-key-hkdf-v1";
  saltHex: string;
  nonceHex: string;
  ciphertextHex: string;
}
export function validateLocalScope(scope: string): string {
  if (typeof scope !== "string" || !scope || new TextEncoder().encode(scope).length > 95 || /[\u0000-\u001f\u007f]/u.test(scope) || /[\ud800-\udfff]/u.test(scope)) fail("invalid-scope");
  return scope;
}
export function validateLocalSecret(value: unknown): LocalSecretV3 {
  const s=object(value as Value,["version","keySource","saltHex","nonceHex","ciphertextHex"]);
  if(s.version!==3 || s.keySource!=="active-key-hkdf-v1" || typeof s.saltHex!=="string" || typeof s.nonceHex!=="string" || typeof s.ciphertextHex!=="string" || s.saltHex.length!==32 || s.nonceHex.length!==24 || s.ciphertextHex.length<34 || s.ciphertextHex.length>1056)fail("invalid-secret");
  unhex(s.saltHex);unhex(s.nonceHex);unhex(s.ciphertextHex);
  return {...s} as unknown as LocalSecretV3;
}
