/**
 * Byte / base64 / hex helpers — isomorphic (browser + Node), no Buffer dependency.
 * The SDK puts base64 on the wire (matching the Python reference `_b64` / `_wire`).
 */

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Standard base64 encode (with padding), isomorphic. */
export function toBase64(bytes: Uint8Array): string {
  // Prefer the platform btoa when available (browser); fall back to a manual encoder so the
  // SDK has no Node Buffer dependency and the integration test runs identically.
  if (typeof btoa === 'function') {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
    return btoa(bin);
  }
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out += B64_CHARS[b0 >> 2];
    out += B64_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? B64_CHARS[b2 & 0x3f] : '=';
  }
  return out;
}

/** Standard base64 decode, isomorphic. */
export function fromBase64(b64: string): Uint8Array {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  const clean = b64.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let bits = 0;
  let val = 0;
  let oi = 0;
  for (let i = 0; i < clean.length; i++) {
    val = (val << 6) | B64_CHARS.indexOf(clean[i]!);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[oi++] = (val >> bits) & 0xff;
    }
  }
  return out;
}

/** Lowercase-hex of bytes. */
export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

/** Decode a hex string (optionally `0x`-prefixed) to bytes. */
export function fromHex(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** UTF-8 encode. */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** UTF-8 decode. */
export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
