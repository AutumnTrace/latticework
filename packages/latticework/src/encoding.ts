// Byte encodings and rounding, FIPS 203 section 4.2.1: Compress and
// Decompress, and ByteEncode and ByteDecode (Algorithms 5 and 6).

import { N, Q } from './params.ts';
import { newPoly, type Poly } from './ntt.ts';

/**
 * ByteEncode_d (Algorithm 5): pack 256 d-bit integers into 32d bytes,
 * least significant bit first.
 */
export function byteEncode(f: Poly, d: number, out: Uint8Array = new Uint8Array(32 * d), offset = 0): Uint8Array {
  let acc = 0;
  let accBits = 0;
  let o = offset;
  for (let i = 0; i < N; i++) {
    acc |= f[i]! << accBits;
    accBits += d;
    while (accBits >= 8) {
      out[o++] = acc & 0xff;
      acc >>>= 8;
      accBits -= 8;
    }
  }
  return out;
}

/**
 * ByteDecode_d (Algorithm 6): the inverse of ByteEncode_d. For d = 12 the
 * 12-bit values are reduced mod q, which is why the encapsulation key needs
 * the modulus check of section 7.2: a value of 3329 or more in the key would
 * otherwise be silently changed.
 */
export function byteDecode(bytes: Uint8Array, d: number, offset = 0): Poly {
  const f = newPoly();
  const mask = (1 << d) - 1;
  let acc = 0;
  let accBits = 0;
  let o = offset;
  for (let i = 0; i < N; i++) {
    while (accBits < d) {
      acc |= bytes[o++]! << accBits;
      accBits += 8;
    }
    const v = acc & mask;
    f[i] = d === 12 ? v % Q : v;
    acc >>>= d;
    accBits -= d;
  }
  return f;
}

/** Encode k polynomials one after another. */
export function byteEncodeVector(v: readonly Poly[], d: number): Uint8Array {
  const out = new Uint8Array(32 * d * v.length);
  v.forEach((f, i) => byteEncode(f, d, out, 32 * d * i));
  return out;
}

export function byteDecodeVector(bytes: Uint8Array, d: number, k: number, offset = 0): Poly[] {
  return Array.from({ length: k }, (_, i) => byteDecode(bytes, d, offset + 32 * d * i));
}

/**
 * Compress_d(x) = round(2^d / q * x) mod 2^d, with round-half-up. q is odd,
 * so 2^d x / q is never exactly halfway and the integer form
 * floor((2^d x + (q - 1) / 2) / q) is exact.
 */
export function compress(f: Poly, d: number): Poly {
  const out = newPoly();
  const mask = (1 << d) - 1;
  for (let i = 0; i < N; i++) out[i] = Math.floor((f[i]! * (1 << d) + (Q - 1) / 2) / Q) & mask;
  return out;
}

/** Decompress_d(y) = round(q / 2^d * y), round-half-up. */
export function decompress(f: Poly, d: number): Poly {
  const out = newPoly();
  const half = 1 << (d - 1);
  for (let i = 0; i < N; i++) out[i] = (f[i]! * Q + half) >>> d;
  return out;
}
