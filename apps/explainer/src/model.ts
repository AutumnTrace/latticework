// Everything the explainer shows, computed from one traced ML-KEM exchange.
// No DOM in here, so the numbers can be unit tested; the sections only draw.

import { mlKem1024, mlKem512, mlKem768, type DecapsulateTrace, type EncapsulateTrace, type MlKem } from '@autumntrace/latticework';
import {
  addInPlace,
  centered,
  compress,
  decompress,
  invNtt,
  multiplyNtts,
  N,
  ntt,
  Q,
  schoolbookMultiply,
  shake128,
  sub,
  type DecryptTrace,
  type EncryptTrace,
  type KeyGenTrace,
  ZETAS,
  type Poly,
} from '@autumntrace/latticework/internals';

export const KEMS = { 512: mlKem512, 768: mlKem768, 1024: mlKem1024 } as const;
export type SetId = keyof typeof KEMS;

/** FIPS 203 Table 1: decryption failure probability per parameter set, as log2. */
export const FAILURE_LOG2: Record<SetId, number> = { 512: -138.8, 768: -164.8, 1024: -174.8 };

type Full<T> = { [K in keyof T]-?: NonNullable<T[K]> };

export interface Exchange {
  set: SetId;
  kem: MlKem;
  d: Uint8Array;
  z: Uint8Array;
  m: Uint8Array;
  keygen: Full<KeyGenTrace>;
  ek: Uint8Array;
  dk: Uint8Array;
  encaps: { hEk: Uint8Array; r: Uint8Array; encrypt: Full<EncryptTrace> };
  /** Bob's shared secret and the ciphertext he sends. */
  bobKey: Uint8Array;
  c: Uint8Array;
  decaps: Full<DecapsulateTrace> & { decrypt: Full<DecryptTrace>; reencrypt: Full<EncryptTrace> };
  /** Alice's shared secret, from decapsulating c. */
  aliceKey: Uint8Array;
  /** Wall-clock time of each traced step in this run, in milliseconds. */
  timings: { keygen: number; encaps: number; decaps: number };
}

function now(): number {
  return globalThis.performance ? performance.now() : Date.now();
}

/** Run one complete, traced exchange from fixed randomness. */
export function runExchange(set: SetId, d: Uint8Array, z: Uint8Array, m: Uint8Array): Exchange {
  const kem = KEMS[set];
  const keygen: KeyGenTrace = {};
  const t0 = now();
  const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygenInternal(d, z, keygen);
  const t1 = now();
  const encaps: EncapsulateTrace = {};
  const { sharedSecret: bobKey, ciphertext: c } = kem.encapsulateInternal(ek, m, encaps);
  const t2 = now();
  const decaps: DecapsulateTrace = {};
  const aliceKey = kem.decapsulateInternal(dk, c, decaps);
  const t3 = now();
  return {
    set,
    kem,
    d,
    z,
    m,
    keygen: keygen as Full<KeyGenTrace>,
    ek,
    dk,
    encaps: encaps as Exchange['encaps'],
    bobKey,
    c,
    decaps: decaps as Exchange['decaps'],
    aliceKey,
    timings: { keygen: t1 - t0, encaps: t2 - t1, decaps: t3 - t2 },
  };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// ----------------------------------------------------------------- noise

function binomial(n: number, k: number): number {
  let r = 1;
  for (let i = 1; i <= k; i++) r = (r * (n - k + i)) / i;
  return r;
}

export interface HistogramBin {
  value: number;
  count: number;
  /** Expected count under the exact distribution. */
  expected: number;
}

/** Histogram of centred coefficients against the CBD_eta probabilities C(2 eta, eta + x) / 4^eta. */
export function cbdHistogram(polys: readonly Poly[], eta: number): HistogramBin[] {
  const total = polys.length * N;
  const bins: HistogramBin[] = [];
  for (let x = -eta; x <= eta; x++) bins.push({ value: x, count: 0, expected: (total * binomial(2 * eta, eta + x)) / 4 ** eta });
  for (const p of polys) for (const c of p) bins[centered(c) + eta]!.count++;
  return bins;
}

/** Centred coefficients of a polynomial, as plain numbers in (-q/2, q/2]. */
export function centeredCoeffs(p: Poly): number[] {
  return Array.from(p, centered);
}

// ---------------------------------------------------------------- SampleNTT

export interface Candidate {
  value: number;
  accepted: boolean;
}

/**
 * The first `count` 12-bit candidates SampleNTT draws for entry (i, j) of
 * the matrix, read straight from SHAKE128(rho || j || i).
 */
export function sampleCandidates(rho: Uint8Array, i: number, j: number, count: number): Candidate[] {
  const bytes = shake128()
    .absorb(rho)
    .absorb(Uint8Array.of(j, i))
    .squeeze(Math.ceil(count / 2) * 3);
  const out: Candidate[] = [];
  for (let p = 0; out.length < count; p += 3) {
    const d1 = bytes[p]! | ((bytes[p + 1]! & 0x0f) << 8);
    const d2 = (bytes[p + 1]! >> 4) | (bytes[p + 2]! << 4);
    out.push({ value: d1, accepted: d1 < Q });
    if (out.length < count) out.push({ value: d2, accepted: d2 < Q });
  }
  return out;
}

// ------------------------------------------------------------ compression

export interface ErrorStats {
  /** Centred rounding error of every coefficient. */
  errors: number[];
  maxAbs: number;
  /** The worst case allowed by the rounding, round(q / 2^(d+1)). */
  bound: number;
}

/** What Compress_d then Decompress_d does to each coefficient. */
export function compressionErrors(polys: readonly Poly[], d: number): ErrorStats {
  const errors: number[] = [];
  for (const p of polys) {
    const back = decompress(compress(p, d), d);
    for (let i = 0; i < N; i++) errors.push(centered((back[i]! - p[i]! + Q) % Q));
  }
  return { errors, maxAbs: Math.max(...errors.map(Math.abs)), bound: Math.round(Q / 2 ** (d + 1)) };
}

// ------------------------------------------------------------- ring maths

/** a * b in R_q through the NTT. */
export function ringMultiply(a: Poly, b: Poly): Poly {
  return invNtt(multiplyNtts(ntt(a), ntt(b)));
}

function innerProduct(a: readonly Poly[], b: readonly Poly[]): Poly {
  const acc = new Uint16Array(N);
  a.forEach((p, i) => addInPlace(acc, ringMultiply(p, b[i]!)));
  return acc;
}

function negate(p: Poly): Poly {
  return p.map((x) => (x === 0 ? 0 : Q - x));
}

export interface NoiseTerm {
  /** How the term is written in the derivation. */
  label: string;
  coeffs: number[];
  maxAbs: number;
  std: number;
}

export interface NoiseBreakdown {
  /** w - mu, centred: what decryption has to round away. */
  noise: number[];
  maxAbs: number;
  /** q/4 rounded: a coefficient decodes correctly while |noise| < this. */
  threshold: number;
  terms: NoiseTerm[];
  /** Whether the terms add up to the observed noise on every coefficient. */
  termsMatch: boolean;
  /** Message bits that decryption got wrong (should be 0). */
  wrongBits: number;
}

function stats(label: string, coeffs: number[]): NoiseTerm {
  const mean = coeffs.reduce((a, b) => a + b, 0) / coeffs.length;
  const variance = coeffs.reduce((a, b) => a + (b - mean) ** 2, 0) / coeffs.length;
  return { label, coeffs, maxAbs: Math.max(...coeffs.map(Math.abs)), std: Math.sqrt(variance) };
}

/**
 * Split the decryption noise into its sources. With t = A s + e,
 * u = A^T y + e1 and v = t^T y + e2 + mu, the receiver's
 *
 *   w = v' - s^T u' = mu + e^T y - s^T e1 + e2 + dv - s^T du
 *
 * where du = u' - u and dv = v' - v are the compression errors. Every term
 * is recomputed here from the traced values and the sum is compared with
 * the w that decryption actually produced.
 */
export function noiseBreakdown(ex: Exchange): NoiseBreakdown {
  const { s, e } = ex.keygen;
  const { y, e1, e2, u, v, mu } = ex.encaps.encrypt;
  const { uPrime, vPrime, w } = ex.decaps.decrypt;

  const du = uPrime.map((p, i) => sub(p, u[i]!));
  const dv = sub(vPrime, v);
  const parts: [string, Poly][] = [
    ['eᵀy', innerProduct(e, y)],
    ['−sᵀe₁', negate(innerProduct(s, e1))],
    ['e₂', e2],
    ['Δv', dv],
    ['−sᵀΔu', negate(innerProduct(s, du))],
  ];
  const sum = new Uint16Array(N);
  for (const [, p] of parts) addInPlace(sum, p);

  const noisePoly = sub(w, mu);
  const noise = centeredCoeffs(noisePoly);
  const threshold = Math.round(Q / 4);
  let wrongBits = 0;
  for (let i = 0; i < N; i++) {
    const bit = (ex.m[i >> 3]! >> (i & 7)) & 1;
    const decoded = (ex.decaps.mPrime[i >> 3]! >> (i & 7)) & 1;
    if (bit !== decoded) wrongBits++;
  }
  return {
    noise,
    maxAbs: Math.max(...noise.map(Math.abs)),
    threshold,
    terms: parts.map(([label, p]) => stats(label, centeredCoeffs(p))),
    termsMatch: sum.every((x, i) => x === noisePoly[i]),
    wrongBits,
  };
}

// -------------------------------------------------------------- the NTT

/** Lengths of the seven NTT layers, in order: 128, 64, ..., 2. */
export const NTT_LAYERS = [128, 64, 32, 16, 8, 4, 2] as const;

/**
 * The rows of layer L - 1 that feed `rows` of layer L (layers counted from
 * 1). A butterfly pairs row j with j XOR len, so going back one layer adds
 * the partner of every row.
 */
export function feedingRows(rows: ReadonlySet<number>, layer: number): Set<number> {
  const len = NTT_LAYERS[layer - 1]!;
  const out = new Set(rows);
  for (const r of rows) out.add(r ^ len);
  return out;
}

/** For each layer 0..7, the rows that output `row` (after layer 7) depends on. */
export function dependencyCone(row: number): Set<number>[] {
  const cone: Set<number>[] = Array.from({ length: 8 }, () => new Set<number>());
  cone[7] = new Set([row]);
  for (let layer = 7; layer >= 1; layer--) cone[layer - 1] = feedingRows(cone[layer]!, layer);
  return cone;
}

/** For each layer 0..7, the rows that input `row` (before layer 1) reaches. */
export function influenceCone(row: number): Set<number>[] {
  const cone: Set<number>[] = [new Set([row])];
  for (let layer = 1; layer <= 7; layer++) {
    const len = NTT_LAYERS[layer - 1]!;
    const next = new Set(cone[layer - 1]);
    for (const r of cone[layer - 1]!) next.add(r ^ len);
    cone.push(next);
  }
  return cone;
}

/** The coefficients after each NTT layer, for drawing the transform as it happens. */
export function nttLayers(f: Poly): Poly[] {
  const states: Poly[] = [f.slice()];
  const a = f.slice();
  let k = 1;
  for (const len of NTT_LAYERS) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = ZETAS[k++]!;
      for (let j = start; j < start + len; j++) {
        const t = (zeta * a[j + len]!) % Q;
        a[j + len] = (a[j]! - t + Q) % Q;
        a[j] = (a[j]! + t) % Q;
      }
    }
    states.push(a.slice());
  }
  return states;
}

export interface MultiplyCheck {
  agree: boolean;
  schoolbookMs: number;
  nttMs: number;
  reps: number;
}

/** Multiply two polynomials both ways, time both, and compare. */
export function multiplyCheck(a: Poly, b: Poly, reps = 20): MultiplyCheck {
  let slow = schoolbookMultiply(a, b);
  const t0 = now();
  for (let i = 0; i < reps; i++) slow = schoolbookMultiply(a, b);
  const t1 = now();
  let fast = ringMultiply(a, b);
  for (let i = 0; i < reps; i++) fast = ringMultiply(a, b);
  const t2 = now();
  return { agree: bytesEqual(new Uint8Array(slow.buffer), new Uint8Array(fast.buffer)), schoolbookMs: (t1 - t0) / reps, nttMs: (t2 - t1) / reps, reps };
}

// ----------------------------------------------------------- tampering

export interface TamperResult {
  byte: number;
  bit: number;
  c: Uint8Array;
  trace: Exchange['decaps'];
  key: Uint8Array;
  /** Message bits that differ between m' and the original m. */
  messageBitsChanged: number;
  /** Bytes where the re-encryption c' differs from the tampered c. */
  ciphertextBytesDiffer: number;
}

/** Flip one bit of the ciphertext and decapsulate again. */
export function tamper(ex: Exchange, byte: number, bit: number): TamperResult {
  const c = ex.c.slice();
  c[byte]! ^= 1 << bit;
  const trace: DecapsulateTrace = {};
  const key = ex.kem.decapsulateInternal(ex.dk, c, trace);
  const full = trace as Exchange['decaps'];
  let messageBitsChanged = 0;
  for (let i = 0; i < 32; i++) {
    let x = full.mPrime[i]! ^ ex.m[i]!;
    while (x) {
      messageBitsChanged += x & 1;
      x >>= 1;
    }
  }
  let ciphertextBytesDiffer = 0;
  for (let i = 0; i < c.length; i++) if (c[i] !== full.cPrime[i]) ciphertextBytesDiffer++;
  return { byte, bit, c, trace: full, key, messageBitsChanged, ciphertextBytesDiffer };
}

export interface FlipStats {
  flips: number;
  rejected: number;
  /** Flips after which decryption still recovered exactly m. */
  messageUnchanged: number;
}

/**
 * Flip ciphertext bits `from` to `to` - 1 (counting bit 0 of byte 0 as 0),
 * one at a time, decapsulate each, and add up what happened.
 */
export function flipRange(ex: Exchange, from: number, to: number, acc: FlipStats = { flips: 0, rejected: 0, messageUnchanged: 0 }): FlipStats {
  const c = ex.c.slice();
  for (let b = from; b < to; b++) {
    c[b >> 3]! ^= 1 << (b & 7);
    const trace: DecapsulateTrace = {};
    ex.kem.decapsulateInternal(ex.dk, c, trace);
    c[b >> 3]! ^= 1 << (b & 7);
    acc.flips++;
    if (!trace.accepted) acc.rejected++;
    if (bytesEqual(trace.mPrime!, ex.m)) acc.messageUnchanged++;
  }
  return acc;
}

/** Which ciphertext field a byte belongs to, and the coefficient(s) it carries bits of. */
export function ciphertextField(ex: Exchange, byte: number): { field: 'c1' | 'c2'; poly: number; coeffs: [number, number] } {
  const { k, du, dv } = ex.kem.params;
  const c1Bytes = 32 * du * k;
  if (byte < c1Bytes) {
    const poly = Math.floor(byte / (32 * du));
    const bitStart = (byte - poly * 32 * du) * 8;
    return { field: 'c1', poly, coeffs: [Math.floor(bitStart / du), Math.floor((bitStart + 7) / du)] };
  }
  const bitStart = (byte - c1Bytes) * 8;
  return { field: 'c2', poly: 0, coeffs: [Math.floor(bitStart / dv), Math.floor((bitStart + 7) / dv)] };
}
