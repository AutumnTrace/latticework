// The explainer's numbers, checked: if these pass, what the page says about
// the exchange it draws is true for that exchange.
import { ntt } from '@autumntrace/latticework/internals';
import { describe, expect, it } from 'vitest';
import {
  bytesEqual,
  cbdHistogram,
  ciphertextField,
  compressionErrors,
  dependencyCone,
  flipRange,
  influenceCone,
  multiplyCheck,
  noiseBreakdown,
  nttLayers,
  runExchange,
  tamper,
  type SetId,
} from '../src/model.ts';

const seed = (label: string, n: number) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + label.length * 7 + label.charCodeAt(i % label.length)) & 0xff);

describe.each([512, 768, 1024] as SetId[])('ML-KEM-%i exchange', (set) => {
  const ex = runExchange(set, seed('d', 32), seed('z', 32), seed('m', 32));

  it('ends with both sides holding the same key', () => {
    expect(bytesEqual(ex.aliceKey, ex.bobKey)).toBe(true);
    expect(ex.decaps.accepted).toBe(true);
  });

  it('decomposes the decryption noise exactly into its five terms', () => {
    const b = noiseBreakdown(ex);
    expect(b.termsMatch).toBe(true);
    expect(b.wrongBits).toBe(0);
    expect(b.maxAbs).toBeLessThan(b.threshold);
    const sum = b.noise.map((_, i) => b.terms.reduce((acc, t) => acc + t.coeffs[i]!, 0));
    // Centred terms can wrap mod q when summed, but at these sizes they never do.
    expect(sum).toEqual(b.noise);
  });

  it('keeps every CBD sample within eta, with the right total', () => {
    const { eta1 } = ex.kem.params;
    const h = cbdHistogram([...ex.keygen.s, ...ex.keygen.e], eta1);
    expect(h.length).toBe(2 * eta1 + 1);
    expect(h.reduce((a, b) => a + b.count, 0)).toBe(2 * ex.kem.params.k * 256);
    expect(h.reduce((a, b) => a + b.expected, 0)).toBeCloseTo(2 * ex.kem.params.k * 256, 6);
  });

  it('reports compression errors within the rounding bound', () => {
    const { du, dv } = ex.kem.params;
    const u = compressionErrors(ex.encaps.encrypt.u, du);
    const v = compressionErrors([ex.encaps.encrypt.v], dv);
    expect(u.maxAbs).toBeLessThanOrEqual(u.bound);
    expect(v.maxAbs).toBeLessThanOrEqual(v.bound);
  });

  it('rejects a tampered ciphertext whichever bit is flipped', () => {
    for (const [byte, bit] of [
      [0, 0],
      [ex.c.length - 1, 7],
      [Math.floor(ex.c.length / 2), 3],
    ] as const) {
      const r = tamper(ex, byte, bit);
      expect(r.trace.accepted).toBe(false);
      expect(bytesEqual(r.key, r.trace.kBar)).toBe(true);
      expect(bytesEqual(r.key, ex.bobKey)).toBe(false);
      expect(r.ciphertextBytesDiffer).toBeGreaterThan(0);
    }
  });

  it('rejects every single-bit flip in a stretch of c₁ and c₂', () => {
    const c2Start = ex.c.length * 8 - 256;
    const a = flipRange(ex, 0, 128);
    const b = flipRange(ex, c2Start, c2Start + 128);
    expect(a.rejected).toBe(128);
    expect(b.rejected).toBe(128);
    // Low-order flips usually leave the decrypted message as it was.
    expect(a.messageUnchanged + b.messageUnchanged).toBeGreaterThan(0);
  });

  it('maps ciphertext bytes to the right field', () => {
    const { k, du } = ex.kem.params;
    expect(ciphertextField(ex, 0)).toEqual({ field: 'c1', poly: 0, coeffs: [0, 0] });
    expect(ciphertextField(ex, 32 * du * k - 1).field).toBe('c1');
    expect(ciphertextField(ex, 32 * du * k)).toEqual({ field: 'c2', poly: 0, coeffs: [0, 1] });
  });
});

describe('NTT diagram', () => {
  it('records the layers of the real NTT', () => {
    const ex = runExchange(768, seed('d', 32), seed('z', 32), seed('m', 32));
    const layers = nttLayers(ex.keygen.s[0]!);
    expect(layers.length).toBe(8);
    expect(layers[7]).toEqual(ntt(ex.keygen.s[0]!));
  });

  it('has every output depend on exactly the 128 inputs of the same parity', () => {
    for (const row of [0, 1, 77, 255]) {
      const cone = dependencyCone(row);
      expect(cone[0]!.size).toBe(128);
      expect([...cone[0]!].every((r) => r % 2 === row % 2)).toBe(true);
      expect(influenceCone(row)[7]!.size).toBe(128);
    }
  });

  it('multiplies the same way with and without the NTT', () => {
    const ex = runExchange(768, seed('d', 32), seed('z', 32), seed('m', 32));
    expect(multiplyCheck(ex.keygen.s[0]!, ex.encaps.encrypt.y[0]!, 2).agree).toBe(true);
  });
});
