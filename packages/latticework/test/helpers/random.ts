// A small seeded generator so unit tests are reproducible without pulling in
// a dependency. Not for keys: those come from crypto.getRandomValues.
import type { Poly } from '../../src/ntt.ts';
import { N, Q } from '../../src/params.ts';
import { shake256 } from '../../src/sha3.ts';

export function seededBytes(label: string, length: number): Uint8Array {
  return shake256().absorb(new TextEncoder().encode(label)).squeeze(length);
}

/** A polynomial with coefficients uniform in [0, q), from a label. */
export function seededPoly(label: string): Poly {
  const bytes = seededBytes(label, 2 * N);
  const f = new Uint16Array(N);
  for (let i = 0; i < N; i++) f[i] = (bytes[2 * i]! | (bytes[2 * i + 1]! << 8)) % Q;
  return f;
}
