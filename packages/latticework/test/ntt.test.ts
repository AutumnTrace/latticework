import { describe, expect, it } from 'vitest';
import { bitRev7, centered, GAMMAS, invNtt, multiplyNtts, N_INV_128, ntt, schoolbookMultiply, ZETAS } from '../src/ntt.ts';
import { N, Q } from '../src/params.ts';
import { seededPoly } from './helpers/random.ts';

describe('NTT constants', () => {
  it('reverses 7-bit indices', () => {
    expect(bitRev7(1)).toBe(64);
    expect(bitRev7(0b0000011)).toBe(0b1100000);
    expect(Array.from({ length: 128 }, (_, i) => bitRev7(bitRev7(i)))).toEqual(Array.from({ length: 128 }, (_, i) => i));
  });

  it('matches the first zetas and gammas listed in FIPS 203 Appendix A', () => {
    expect(Array.from(ZETAS.subarray(0, 8))).toEqual([1, 1729, 2580, 3289, 2642, 630, 1897, 848]);
    expect(Array.from(GAMMAS.subarray(0, 8))).toEqual([17, 3312, 2761, 568, 583, 2746, 2649, 680]);
  });

  it('uses 3303 as the inverse of 128', () => {
    expect((128 * N_INV_128) % Q).toBe(1);
  });
});

describe('NTT', () => {
  it('round-trips through the inverse', () => {
    for (let i = 0; i < 20; i++) {
      const f = seededPoly(`round-trip ${i}`);
      expect(invNtt(ntt(f))).toEqual(f);
    }
  });

  it('turns ring multiplication into base-case products', () => {
    for (let i = 0; i < 10; i++) {
      const f = seededPoly(`mul f ${i}`);
      const g = seededPoly(`mul g ${i}`);
      expect(invNtt(multiplyNtts(ntt(f), ntt(g)))).toEqual(schoolbookMultiply(f, g));
    }
  });

  it('wraps X^255 * X to -1, because X^256 = -1 in R_q', () => {
    const x255 = new Uint16Array(N);
    x255[255] = 1;
    const x = new Uint16Array(N);
    x[1] = 1;
    const product = invNtt(multiplyNtts(ntt(x255), ntt(x)));
    const expected = new Uint16Array(N);
    expected[0] = Q - 1;
    expect(product).toEqual(expected);
  });

  it('is linear', () => {
    const f = seededPoly('lin f');
    const g = seededPoly('lin g');
    const sum = f.map((a, i) => (a + g[i]!) % Q);
    const nf = ntt(f);
    const ng = ntt(g);
    expect(ntt(sum)).toEqual(nf.map((a, i) => (a + ng[i]!) % Q));
  });
});

describe('centered', () => {
  it('maps [0, q) onto (-q/2, q/2]', () => {
    expect(centered(0)).toBe(0);
    expect(centered(1664)).toBe(1664);
    expect(centered(1665)).toBe(-1664);
    expect(centered(Q - 1)).toBe(-1);
  });
});
