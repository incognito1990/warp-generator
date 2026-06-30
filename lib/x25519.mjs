import { webcrypto as crypto } from 'node:crypto';

/**
 * X25519 key generation (RFC 7748) for WireGuard-compatible keypairs.
 */

const P = (1n << 255n) - 19n;
const A24 = 121665n;

function cswap(swap, a, b) {
  const mask = (swap === 1n ? (1n << 256n) - 1n : 0n) & (a ^ b);
  return [a ^ mask, b ^ mask];
}

function pow(a, e) {
  let r = 1n;
  a %= P;
  while (e > 0n) {
    if (e & 1n) r = (r * a) % P;
    a = (a * a) % P;
    e >>= 1n;
  }
  return r;
}

function inv(a) {
  return pow(a, P - 2n);
}

function decodeScalar(k) {
  const bytes = Uint8Array.from(k);
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  let s = 0n;
  for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(bytes[i]);
  return s;
}

function decodeU(u) {
  const bytes = Uint8Array.from(u);
  bytes[31] &= 127;
  let s = 0n;
  for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(bytes[i]);
  return s % P;
}

function encodeU(n) {
  n %= P;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function scalarMult(privateKeyBytes, publicKeyBytes) {
  const k = decodeScalar(privateKeyBytes);
  const x1 = decodeU(publicKeyBytes);
  let x2 = 1n;
  let z2 = 0n;
  let x3 = x1;
  let z3 = 1n;
  let swap = 0n;

  for (let t = 254; t >= 0; t--) {
    const kt = (k >> BigInt(t)) & 1n;
    swap ^= kt;
    [x2, x3] = cswap(swap, x2, x3);
    [z2, z3] = cswap(swap, z2, z3);
    swap = kt;

    const sum = (x2 + z2) % P;
    const aa = (sum * sum) % P;
    const diff = ((x2 - z2) % P + P) % P;
    const bb = (diff * diff) % P;
    const e = ((aa - bb) % P + P) % P;
    const c = (x3 + z3) % P;
    const d = ((x3 - z3) % P + P) % P;
    const da = (d * sum) % P;
    const cb = (c * diff) % P;

    let x3n = (da + cb) % P;
    x3n = (x3n * x3n) % P;
    let z3n = ((da - cb) % P + P) % P;
    z3n = (z3n * z3n) % P;
    z3n = (z3n * x1) % P;

    x2 = (aa * bb) % P;
    z2 = (e * ((aa + (A24 * e) % P) % P)) % P;
    x3 = x3n;
    z3 = z3n;
  }

  [x2, x3] = cswap(swap, x2, x3);
  [z2, z3] = cswap(swap, z2, z3);
  return encodeU((x2 * inv(z2)) % P);
}

const BASE_POINT = new Uint8Array(32);
BASE_POINT[0] = 9;

function clampPrivateKey(raw) {
  const bytes = Uint8Array.from(raw);
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes;
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

/** Generate a WireGuard keypair (base64 private + public keys). */
export function generateKeypair() {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const privateKey = clampPrivateKey(raw);
  const publicKey = scalarMult(privateKey, BASE_POINT);
  return {
    privateKey: toBase64(privateKey),
    publicKey: toBase64(publicKey),
  };
}
