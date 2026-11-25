// Sampling, FIPS 203 section 4.2.2: uniform polynomials in the NTT domain
// from a seed (SampleNTT, Algorithm 7) and small "noise" polynomials from a
// centred binomial distribution (SamplePolyCBD, Algorithm 8).

import { N, Q } from './params.ts';
import { newPoly, type Poly } from './ntt.ts';
import { shake128, shake256 } from './sha3.ts';

export interface SampleNttStats {
  /** 12-bit candidates drawn from the XOF, accepted or not. */
  candidates: number;
  /** Candidates that were 3329 or more and thrown away. */
  rejected: number;
  /** XOF output consumed, in bytes. */
  bytes: number;
}

const SHAKE128_RATE = 168; // a whole number of 3-byte groups

/**
 * SampleNTT (Algorithm 7): rejection-sample 256 coefficients in [0, q) from
 * SHAKE128(seed). Each 3 bytes give two 12-bit candidates; a candidate of
 * 3329 or more is discarded. The algorithm reads the XOF 3 bytes at a time;
 * reading one 168-byte block at a time is the same stream.
 *
 * `seed` is the 34 bytes rho || j || i.
 */
export function sampleNtt(seed: Uint8Array, stats?: SampleNttStats): Poly {
  if (seed.length !== 34) throw new RangeError(`SampleNTT takes a 34-byte seed, got ${seed.length}`);
  const xof = shake128().absorb(seed);
  const a = newPoly();
  const buf = new Uint8Array(SHAKE128_RATE);
  let j = 0;
  let candidates = 0;
  let bytes = 0;
  while (j < N) {
    xof.squeezeInto(buf);
    for (let p = 0; p < SHAKE128_RATE && j < N; p += 3) {
      const b0 = buf[p]!;
      const b1 = buf[p + 1]!;
      const b2 = buf[p + 2]!;
      const d1 = b0 | ((b1 & 0x0f) << 8);
      const d2 = (b1 >> 4) | (b2 << 4);
      bytes += 3;
      candidates++;
      if (d1 < Q) a[j++] = d1;
      if (j < N) {
        candidates++;
        if (d2 < Q) a[j++] = d2;
      }
    }
  }
  if (stats) {
    stats.candidates += candidates;
    stats.rejected += candidates - N;
    stats.bytes += bytes;
  }
  return a;
}

/**
 * SamplePolyCBD_eta (Algorithm 8): each coefficient is the difference of
 * two sums of eta random bits, so it lies in [-eta, eta] with binomial
 * weights. Takes 64 eta bytes, read least significant bit first.
 */
export function samplePolyCbd(bytes: Uint8Array, eta: number): Poly {
  if (bytes.length !== 64 * eta) throw new RangeError(`SamplePolyCBD_${eta} takes ${64 * eta} bytes, got ${bytes.length}`);
  const f = newPoly();
  const bit = (k: number) => (bytes[k >> 3]! >> (k & 7)) & 1;
  for (let i = 0; i < N; i++) {
    let x = 0;
    let y = 0;
    const base = 2 * i * eta;
    for (let j = 0; j < eta; j++) {
      x += bit(base + j);
      y += bit(base + eta + j);
    }
    f[i] = x >= y ? x - y : x - y + Q;
  }
  return f;
}

/** PRF_eta(s, b) = SHAKE256(s || b), 64 eta bytes (FIPS 203 eq. 4.3). */
export function prf(eta: number, s: Uint8Array, b: number): Uint8Array {
  return shake256()
    .absorb(s)
    .absorb(Uint8Array.of(b))
    .squeeze(64 * eta);
}
