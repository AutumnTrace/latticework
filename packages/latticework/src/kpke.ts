// K-PKE, the IND-CPA public-key encryption scheme inside ML-KEM, FIPS 203
// section 5 (Algorithms 13, 14 and 15). Not meant to be used on its own:
// ML-KEM wraps it in the Fujisaki-Okamoto transform, which is what makes the
// result safe against chosen-ciphertext attacks.
//
// Every function takes an optional trace object. When one is passed, the
// intermediate values are copied into it as they are computed. That is how
// the explainer shows real numbers without a second implementation that
// could drift from this one.

import { byteDecode, byteDecodeVector, byteEncode, byteEncodeVector, compress, decompress } from './encoding.ts';
import { addInPlace, invNttInPlace, multiplyNttsAcc, newPoly, ntt, sub, type Poly } from './ntt.ts';
import type { ParameterSet } from './params.ts';
import { prf, sampleNtt, samplePolyCbd, type SampleNttStats } from './sampling.ts';
import { sha3_512 } from './sha3.ts';

/** G(c) = SHA3-512(c), split into two 32-byte halves (FIPS 203 eq. 4.5). */
export function G(...parts: Uint8Array[]): [Uint8Array, Uint8Array] {
  const out = sha3_512(...parts);
  return [out.subarray(0, 32), out.subarray(32, 64)];
}

/**
 * The matrix A-hat, expanded from rho. Entry (i, j) is SampleNTT(rho || j || i):
 * column index first. Getting that order backwards still gives a working
 * KEM, just not ML-KEM, and the NIST vectors catch it at once.
 */
export function expandMatrix(rho: Uint8Array, k: number, stats?: SampleNttStats): Poly[][] {
  const seed = new Uint8Array(34);
  seed.set(rho);
  return Array.from({ length: k }, (_row, i) =>
    Array.from({ length: k }, (_col, j) => {
      seed[32] = j;
      seed[33] = i;
      return sampleNtt(seed, stats);
    }),
  );
}

/** k noise polynomials from PRF_eta(seed, N), N = n0, n0 + 1, ... */
function sampleNoiseVector(seed: Uint8Array, eta: number, k: number, n0: number): Poly[] {
  return Array.from({ length: k }, (_, i) => samplePolyCbd(prf(eta, seed, n0 + i), eta));
}

/** sum_j A[i][j] * x[j] in the NTT domain, or with A transposed. */
function matrixVector(a: Poly[][], x: Poly[], transpose: boolean): Poly[] {
  const k = x.length;
  return Array.from({ length: k }, (_, i) => {
    const acc = newPoly();
    for (let j = 0; j < k; j++) multiplyNttsAcc(acc, transpose ? a[j]![i]! : a[i]![j]!, x[j]!);
    return acc;
  });
}

/** The inner product sum_i a[i] * b[i] in the NTT domain. */
function innerProduct(a: Poly[], b: Poly[]): Poly {
  const acc = newPoly();
  for (let i = 0; i < a.length; i++) multiplyNttsAcc(acc, a[i]!, b[i]!);
  return acc;
}

export interface KeyGenTrace {
  rho?: Uint8Array;
  sigma?: Uint8Array;
  aHat?: Poly[][];
  sampling?: SampleNttStats;
  s?: Poly[];
  e?: Poly[];
  sHat?: Poly[];
  eHat?: Poly[];
  tHat?: Poly[];
}

/** K-PKE.KeyGen (Algorithm 13). Returns the 384k + 32 byte encryption key and the 384k byte decryption key. */
export function kpkeKeyGen(params: ParameterSet, d: Uint8Array, trace?: KeyGenTrace): { ek: Uint8Array; dk: Uint8Array } {
  // The byte k is appended for domain separation between parameter sets;
  // it is in the final FIPS 203 but not in round-3 Kyber or the FIPS 203
  // draft (ipd), which hashed d alone.
  const [rho, sigma] = G(d, Uint8Array.of(params.k));
  return kpkeKeyGenFromSeeds(params, rho, sigma, trace);
}

/**
 * Algorithm 13 from step 2 on: everything after (rho, sigma) = G(d || k).
 * Split out so tests can run vectors made for the FIPS 203 draft, which
 * differs only in step 1, through the rest of the real key generation.
 */
export function kpkeKeyGenFromSeeds(params: ParameterSet, rho: Uint8Array, sigma: Uint8Array, trace?: KeyGenTrace): { ek: Uint8Array; dk: Uint8Array } {
  const { k, eta1 } = params;
  const sampling: SampleNttStats = { candidates: 0, rejected: 0, bytes: 0 };
  const aHat = expandMatrix(rho, k, sampling);
  const s = sampleNoiseVector(sigma, eta1, k, 0);
  const e = sampleNoiseVector(sigma, eta1, k, k);
  const sHat = s.map(ntt);
  const eHat = e.map(ntt);
  const tHat = matrixVector(aHat, sHat, false).map((t, i) => addInPlace(t, eHat[i]!));

  const ek = new Uint8Array(384 * k + 32);
  ek.set(byteEncodeVector(tHat, 12));
  ek.set(rho, 384 * k);
  const dk = byteEncodeVector(sHat, 12);

  if (trace) Object.assign(trace, { rho: rho.slice(), sigma: sigma.slice(), aHat, sampling, s, e, sHat, eHat, tHat });
  return { ek, dk };
}

export interface EncryptTrace {
  tHat?: Poly[];
  rho?: Uint8Array;
  aHat?: Poly[][];
  y?: Poly[];
  e1?: Poly[];
  e2?: Poly;
  yHat?: Poly[];
  /** u before compression. */
  u?: Poly[];
  /** The message bits scaled to 0 or round(q/2) = 1665. */
  mu?: Poly;
  /** v before compression. */
  v?: Poly;
  /** Compressed u and v, the integers that are written into the ciphertext. */
  uCompressed?: Poly[];
  vCompressed?: Poly;
}

/** K-PKE.Encrypt (Algorithm 14): encrypt the 32-byte message m with randomness r. */
export function kpkeEncrypt(params: ParameterSet, ek: Uint8Array, m: Uint8Array, r: Uint8Array, trace?: EncryptTrace): Uint8Array {
  const { k, eta1, eta2, du, dv } = params;
  const tHat = byteDecodeVector(ek, 12, k);
  const rho = ek.subarray(384 * k, 384 * k + 32);
  const aHat = expandMatrix(rho, k);

  const y = sampleNoiseVector(r, eta1, k, 0);
  const e1 = sampleNoiseVector(r, eta2, k, k);
  const e2 = samplePolyCbd(prf(eta2, r, 2 * k), eta2);
  const yHat = y.map(ntt);

  const u = matrixVector(aHat, yHat, true).map((p, i) => addInPlace(invNttInPlace(p), e1[i]!));
  const mu = decompress(byteDecode(m, 1), 1);
  const v = addInPlace(addInPlace(invNttInPlace(innerProduct(tHat, yHat)), e2), mu);

  const uCompressed = u.map((p) => compress(p, du));
  const vCompressed = compress(v, dv);
  const c = new Uint8Array(params.ciphertextBytes);
  c.set(byteEncodeVector(uCompressed, du));
  byteEncode(vCompressed, dv, c, 32 * du * k);

  if (trace) Object.assign(trace, { tHat, rho: rho.slice(), aHat, y, e1, e2, yHat, u, mu, v, uCompressed, vCompressed });
  return c;
}

export interface DecryptTrace {
  /** u and v as recovered from the ciphertext (decompressed). */
  uPrime?: Poly[];
  vPrime?: Poly;
  sHat?: Poly[];
  /** w = v' - s^T u': the message bits scaled to 0 or 1665, plus noise. */
  w?: Poly;
}

/** K-PKE.Decrypt (Algorithm 15): recover the 32-byte message. */
export function kpkeDecrypt(params: ParameterSet, dk: Uint8Array, c: Uint8Array, trace?: DecryptTrace): Uint8Array {
  const { k, du, dv } = params;
  const uPrime = byteDecodeVector(c, du, k).map((p) => decompress(p, du));
  const vPrime = decompress(byteDecode(c, dv, 32 * du * k), dv);
  const sHat = byteDecodeVector(dk, 12, k);
  const w = sub(vPrime, invNttInPlace(innerProduct(sHat, uPrime.map(ntt))));
  const m = byteEncode(compress(w, 1), 1);
  if (trace) Object.assign(trace, { uPrime, vPrime, sHat, w });
  return m;
}
