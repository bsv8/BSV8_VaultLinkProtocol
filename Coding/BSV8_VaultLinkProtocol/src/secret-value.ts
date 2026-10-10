import type {Value} from "./cbor.js";
/** Internal ownership cleanup for rejected/discarded decoded secret payloads. */
export function wipeResultBytes(value: Value): void {
  const pending: Value[] = [value], visited = new Set<object>();
  while (pending.length) {
    const item = pending.pop()!;
    if (item instanceof Uint8Array) item.fill(0);
    else if (item && typeof item === "object" && !visited.has(item)) {
      visited.add(item);
      pending.push(...(Array.isArray(item) ? item : Object.values(item)));
    }
  }
}
