import { describe, expect, it } from 'vitest';
import { byteDecode, byteEncode, compress, decompress } from '../src/encoding.ts';
import { centered } from '../src/ntt.ts';
import { N, Q } from '../src/params.ts';
import { prf, sampleNtt, samplePolyCbd, type SampleNttStats } from '../src/sampling.ts';
import { seededBytes, seededPoly } from './helpers/random.ts';

describe('ByteEncode / ByteDecode', () => {
  it('round-trips every width from 1 to 12', () => {
    for (let d = 1; d <= 12; d++) {
      const f = seededPoly(`enc ${d}`).map((x) => (d === 12 ? x : x & ((1 << d) - 1)));
      const bytes = byteEncode(f, d);
      expect(bytes.length).toBe(32 * d);
      expect(byteDecode(bytes, d)).toEqual(f);
    }
  });

  it('packs least significant bit first', () => {
    const f = new Uint16Array(N);
    f[0] = 1;
    f[1] = 0b10;
    expect(Array.from(byteEncode(f, 2).subarray(0, 2))).toEqual([0b1001, 0]);
  });

  it('reduces out-of-range 12-bit values mod q, which the key check has to catch', () => {
    const bytes = new Uint8Array(384);
    bytes[0] = 0xff;
    bytes[1] = 0x0f; // first coefficient = 4095
    expect(byteDecode(bytes, 12)[0]).toBe(4095 - Q);
  });
});

describe('Compress / Decompress', () => {
  it('loses at most round(q / 2^(d+1)) per coefficient, over every value in Z_q', () => {
    for (const d of [1, 4, 5, 10, 11]) {
      const bound = Math.round(Q / 2 ** (d + 1));
      let worst = 0;
      for (let start = 0; start < Q; start += N) {
        const f = Uint16Array.from({ length: N }, (_, i) => Math.min(start + i, Q - 1));
        const back = decompress(compress(f, d), d);
        for (let i = 0; i < N; i++) worst = Math.max(worst, Math.abs(centered((back[i]! - f[i]! + Q) % Q)));
      }
      expect(worst, `d = ${d}`).toBeLessThanOrEqual(bound);
    }
  });

  it('sends Compress_1 to the nearer of 0 and q/2', () => {
    const f = Uint16Array.from({ length: N }, (_, i) => [0, 832, 833, 1664, 2496, 2497, 3328][i % 7]!);
    expect(Array.from(compress(f, 1).subarray(0, 7))).toEqual([0, 0, 1, 1, 1, 0, 0]);
    expect(decompress(new Uint16Array(N).fill(1), 1)[0]).toBe(1665);
  });
});

describe('sampling', () => {
  it('SampleNTT gives 256 coefficients below q and counts its rejections', () => {
    const seed = new Uint8Array(34);
    seed.set(seededBytes('rho', 32));
    const stats: SampleNttStats = { candidates: 0, rejected: 0, bytes: 0 };
    const a = sampleNtt(seed, stats);
    expect(a.every((x) => x < Q)).toBe(true);
    expect(stats.candidates - stats.rejected).toBe(N);
    expect(stats.bytes).toBeGreaterThanOrEqual(384);
  });

  it('SamplePolyCBD stays within [-eta, eta]', () => {
    for (const eta of [2, 3]) {
      for (let b = 0; b < 8; b++) {
        const f = samplePolyCbd(prf(eta, seededBytes(`cbd ${eta}`, 32), b), eta);
        expect(f.every((x) => Math.abs(centered(x)) <= eta)).toBe(true);
      }
    }
  });

  it('SamplePolyCBD of all-ones input is all zeros (eta ones minus eta ones)', () => {
    expect(samplePolyCbd(new Uint8Array(128).fill(0xff), 2).every((x) => x === 0)).toBe(true);
  });
});
