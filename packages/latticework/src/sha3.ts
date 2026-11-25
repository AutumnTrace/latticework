// SHA3-256, SHA3-512, SHAKE128 and SHAKE256 (FIPS 202) on top of the sponge
// in keccak.ts. These are the four Keccak instances ML-KEM needs; SHA3-224
// and SHA3-384 would be one line each but nothing here uses them.

import { KeccakSponge } from './keccak.ts';

const SHA3_SUFFIX = 0x06;
const SHAKE_SUFFIX = 0x1f;

/** Rate in bytes: 200 - 2 * (security level in bytes). */
const RATE = {
  sha3_256: 136,
  sha3_512: 72,
  shake128: 168,
  shake256: 136,
} as const;

/** Concatenate byte strings, the `||` of the standards. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const p of parts) length += p.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function hash(rate: number, outLen: number, parts: Uint8Array[]): Uint8Array {
  const sponge = new KeccakSponge(rate, SHA3_SUFFIX);
  for (const p of parts) sponge.absorb(p);
  return sponge.squeeze(outLen);
}

/** SHA3-256 of the concatenation of `parts`. 32 bytes. */
export function sha3_256(...parts: Uint8Array[]): Uint8Array {
  return hash(RATE.sha3_256, 32, parts);
}

/** SHA3-512 of the concatenation of `parts`. 64 bytes. */
export function sha3_512(...parts: Uint8Array[]): Uint8Array {
  return hash(RATE.sha3_512, 64, parts);
}

/**
 * An extendable-output function. Absorb everything first, then call
 * `squeeze` as many times as you like: the output is one continuous stream.
 */
export interface Xof {
  absorb(data: Uint8Array): Xof;
  squeeze(length: number): Uint8Array;
  squeezeInto(out: Uint8Array): Uint8Array;
}

/** A fresh SHAKE128 instance (rate 168 bytes). */
export function shake128(): Xof {
  return new KeccakSponge(RATE.shake128, SHAKE_SUFFIX);
}

/** A fresh SHAKE256 instance (rate 136 bytes). */
export function shake256(): Xof {
  return new KeccakSponge(RATE.shake256, SHAKE_SUFFIX);
}

export type Sha3Function = 'sha3-256' | 'sha3-512' | 'shake128' | 'shake256';

/**
 * Hash a message whose length is not a whole number of bytes, and return
 * `outBits` bits of output. Bits are packed least significant bit first
 * within each byte, the order FIPS 202 uses (its Appendix B.1). Unused high
 * bits of the last input byte are ignored and unused high bits of the last
 * output byte are zero.
 *
 * Only the NIST test vectors need this; real protocols hash bytes.
 */
export function keccakBits(fn: Sha3Function, message: Uint8Array, messageBits: number, outBits?: number): Uint8Array {
  const rate = fn === 'sha3-256' ? RATE.sha3_256 : fn === 'sha3-512' ? RATE.sha3_512 : fn === 'shake128' ? RATE.shake128 : RATE.shake256;
  const suffix = fn.startsWith('sha3') ? SHA3_SUFFIX : SHAKE_SUFFIX;
  const fixed = fn === 'sha3-256' ? 256 : fn === 'sha3-512' ? 512 : undefined;
  const bitsOut = fixed ?? outBits;
  if (bitsOut === undefined) throw new TypeError(`${fn} needs an output length`);
  if (messageBits > message.length * 8) throw new RangeError('messageBits is longer than the message');

  const sponge = new KeccakSponge(rate, suffix);
  const whole = Math.floor(messageBits / 8);
  const rest = messageBits % 8;
  sponge.absorb(message.subarray(0, whole));
  if (rest > 0) sponge.absorbFinalBits(message[whole]!, rest);
  const out = sponge.squeeze(Math.ceil(bitsOut / 8));
  if (bitsOut % 8 !== 0) out[out.length - 1]! &= (1 << (bitsOut % 8)) - 1;
  return out;
}
