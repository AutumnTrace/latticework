import { describe, expect, it } from 'vitest';
import { ML_KEM_1024, ML_KEM_512, ML_KEM_768, N, PARAMETER_SETS, parameterSetByName, Q, ZETA } from '../src/params.ts';

function pow(b: number, e: number): number {
  let r = 1;
  for (let i = 0; i < e; i++) r = (r * b) % Q;
  return r;
}

describe('parameter sets', () => {
  it('match the byte sizes in FIPS 203 Table 3', () => {
    const sizes = PARAMETER_SETS.map((p) => [p.name, p.encapsulationKeyBytes, p.decapsulationKeyBytes, p.ciphertextBytes]);
    expect(sizes).toEqual([
      ['ML-KEM-512', 800, 1632, 768],
      ['ML-KEM-768', 1184, 2400, 1088],
      ['ML-KEM-1024', 1568, 3168, 1568],
    ]);
  });

  it('use the Table 2 values', () => {
    expect([ML_KEM_512.k, ML_KEM_512.eta1, ML_KEM_512.eta2, ML_KEM_512.du, ML_KEM_512.dv]).toEqual([2, 3, 2, 10, 4]);
    expect([ML_KEM_768.k, ML_KEM_768.eta1, ML_KEM_768.eta2, ML_KEM_768.du, ML_KEM_768.dv]).toEqual([3, 2, 2, 10, 4]);
    expect([ML_KEM_1024.k, ML_KEM_1024.eta1, ML_KEM_1024.eta2, ML_KEM_1024.du, ML_KEM_1024.dv]).toEqual([4, 2, 2, 11, 5]);
  });

  it('has 17 as a primitive 256th root of unity mod q', () => {
    expect(pow(ZETA, N)).toBe(1);
    expect(pow(ZETA, N / 2)).toBe(Q - 1); // so no smaller power is 1
  });

  it('looks sets up by name', () => {
    expect(parameterSetByName('ML-KEM-768')).toBe(ML_KEM_768);
    expect(() => parameterSetByName('Kyber768')).toThrow(/unknown parameter set/);
  });
});
