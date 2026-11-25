// Arithmetic in R_q = Z_q[X] / (X^256 + 1) and its NTT representation,
// FIPS 203 sections 4.3 and 4.3.1 (Algorithms 9 to 12).
//
// A polynomial is a Uint16Array of 256 coefficients, always reduced to
// [0, q). Every product of two reduced values is below 3329^2 < 2^24, so
// plain JavaScript numbers (and the int32 fast paths V8 picks for them)
// are exact.
//
// X^256 + 1 does not split into linear factors mod 3329: 17 is only a
// 256th root of unity, not a 512th. So the NTT stops one layer early and
// leaves 128 degree-1 remainders, one per factor X^2 - zeta^(2 BitRev7(i) + 1).
// Multiplying in the NTT domain is therefore not coefficient-wise: each pair
// of coefficients is multiplied as a small polynomial mod its own X^2 - gamma
// (BaseCaseMultiply).

import { N, Q, ZETA } from './params.ts';

export type Poly = Uint16Array;

/** Reverse the low 7 bits of i. */
export function bitRev7(i: number): number {
  let r = 0;
  for (let b = 0; b < 7; b++) r |= ((i >> b) & 1) << (6 - b);
  return r;
}

function powMod(base: number, exp: number): number {
  let result = 1;
  let b = base % Q;
  let e = exp;
  while (e > 0) {
    if (e & 1) result = (result * b) % Q;
    b = (b * b) % Q;
    e >>= 1;
  }
  return result;
}

/** zeta^BitRev7(i) mod q for i = 0..127, the twiddle factors of the NTT. */
export const ZETAS: Uint16Array = Uint16Array.from({ length: 128 }, (_, i) => powMod(ZETA, bitRev7(i)));

/** zeta^(2 BitRev7(i) + 1) mod q for i = 0..127, the moduli of the base-case products. */
export const GAMMAS: Uint16Array = Uint16Array.from({ length: 128 }, (_, i) => powMod(ZETA, 2 * bitRev7(i) + 1));

/** 128^-1 mod q, the scaling at the end of the inverse NTT. */
export const N_INV_128 = 3303;

export function newPoly(): Poly {
  return new Uint16Array(N);
}

/** NTT in place (Algorithm 9). Input and output coefficients are in [0, q). */
export function nttInPlace(f: Poly): Poly {
  let i = 1;
  for (let len = 128; len >= 2; len >>= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = ZETAS[i++]!;
      for (let j = start; j < start + len; j++) {
        const t = (zeta * f[j + len]!) % Q;
        const a = f[j]!;
        f[j + len] = a >= t ? a - t : a - t + Q;
        const s = a + t;
        f[j] = s >= Q ? s - Q : s;
      }
    }
  }
  return f;
}

/** Inverse NTT in place (Algorithm 10). */
export function invNttInPlace(f: Poly): Poly {
  let i = 127;
  for (let len = 2; len <= 128; len <<= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = ZETAS[i--]!;
      for (let j = start; j < start + len; j++) {
        const t = f[j]!;
        const b = f[j + len]!;
        const s = t + b;
        f[j] = s >= Q ? s - Q : s;
        f[j + len] = (zeta * (b >= t ? b - t : b - t + Q)) % Q;
      }
    }
  }
  for (let j = 0; j < N; j++) f[j] = (f[j]! * N_INV_128) % Q;
  return f;
}

export const ntt = (f: Poly): Poly => nttInPlace(f.slice());
export const invNtt = (f: Poly): Poly => invNttInPlace(f.slice());

/**
 * Product of two polynomials in the NTT domain (Algorithms 11 and 12),
 * accumulated into `acc`: acc += f * g.
 */
export function multiplyNttsAcc(acc: Poly, f: Poly, g: Poly): Poly {
  for (let i = 0; i < 128; i++) {
    const a0 = f[2 * i]!;
    const a1 = f[2 * i + 1]!;
    const b0 = g[2 * i]!;
    const b1 = g[2 * i + 1]!;
    // (a0 + a1 X)(b0 + b1 X) mod (X^2 - gamma)
    const c0 = (a0 * b0 + ((a1 * b1) % Q) * GAMMAS[i]!) % Q;
    const c1 = (a0 * b1 + a1 * b0) % Q;
    acc[2 * i] = (acc[2 * i]! + c0) % Q;
    acc[2 * i + 1] = (acc[2 * i + 1]! + c1) % Q;
  }
  return acc;
}

/** f * g in the NTT domain, as a new polynomial. */
export function multiplyNtts(f: Poly, g: Poly): Poly {
  return multiplyNttsAcc(newPoly(), f, g);
}

/** acc += f, coefficient-wise mod q. */
export function addInPlace(acc: Poly, f: Poly): Poly {
  for (let j = 0; j < N; j++) {
    const s = acc[j]! + f[j]!;
    acc[j] = s >= Q ? s - Q : s;
  }
  return acc;
}

/** f - g, coefficient-wise mod q, as a new polynomial. */
export function sub(f: Poly, g: Poly): Poly {
  const out = newPoly();
  for (let j = 0; j < N; j++) {
    const d = f[j]! - g[j]!;
    out[j] = d < 0 ? d + Q : d;
  }
  return out;
}

/**
 * Schoolbook multiplication in R_q, O(n^2). Not used by the KEM: it is the
 * reference the NTT path is tested against, and what the explainer uses to
 * show that the two agree.
 */
export function schoolbookMultiply(f: Poly, g: Poly): Poly {
  const acc = new Float64Array(2 * N);
  for (let i = 0; i < N; i++) {
    const fi = f[i]!;
    if (fi === 0) continue;
    for (let j = 0; j < N; j++) acc[i + j] = (acc[i + j]! + fi * g[j]!) % Q;
  }
  // X^256 = -1, so the top half folds back in with a minus sign.
  const out = newPoly();
  for (let i = 0; i < N; i++) out[i] = (acc[i]! - acc[i + N]! + Q) % Q;
  return out;
}

/** The representative of x mod q in (-q/2, q/2]. */
export function centered(x: number): number {
  return x > (Q - 1) / 2 ? x - Q : x;
}
