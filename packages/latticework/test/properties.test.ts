// Properties that should hold for every input, checked with fast-check.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { byteDecode, byteEncode, compress, decompress } from '../src/encoding.ts';
import { mlKem1024, mlKem512, mlKem768 } from '../src/index.ts';
import { J } from '../src/mlkem.ts';
import { centered, invNtt, multiplyNtts, ntt, schoolbookMultiply } from '../src/ntt.ts';
import { N, Q } from '../src/params.ts';

const bytes = (length: number) => fc.uint8Array({ minLength: length, maxLength: length });
const poly = (max = Q - 1) => fc.array(fc.integer({ min: 0, max }), { minLength: N, maxLength: N }).map((a) => Uint16Array.from(a));

describe.each([mlKem512, mlKem768, mlKem1024].map((kem) => [kem.params.name, kem] as const))('%s', (_name, kem) => {
  it('decapsulation recovers the shared secret for any seed and message', () => {
    fc.assert(
      fc.property(bytes(64), bytes(32), (seed, m) => {
        const { encapsulationKey, decapsulationKey } = kem.keygen(seed);
        const { sharedSecret, ciphertext } = kem.encapsulateInternal(encapsulationKey, m);
        expect(kem.decapsulate(decapsulationKey, ciphertext)).toEqual(sharedSecret);
      }),
      { numRuns: 100 },
    );
  });

  it('flipping any one ciphertext bit yields the implicit-rejection key J(z || c)', () => {
    const bits = kem.params.ciphertextBytes * 8;
    fc.assert(
      fc.property(bytes(64), bytes(32), fc.integer({ min: 0, max: bits - 1 }), (seed, m, bit) => {
        const { encapsulationKey, decapsulationKey } = kem.keygen(seed);
        const { sharedSecret, ciphertext } = kem.encapsulateInternal(encapsulationKey, m);
        ciphertext[bit >> 3]! ^= 1 << (bit & 7);
        const z = decapsulationKey.subarray(decapsulationKey.length - 32);
        const key = kem.decapsulate(decapsulationKey, ciphertext);
        expect(key).toEqual(J(z, ciphertext));
        expect(key).not.toEqual(sharedSecret);
      }),
      { numRuns: 200 },
    );
  });

  it('every generated key passes both key checks', () => {
    fc.assert(
      fc.property(bytes(64), (seed) => {
        const { encapsulationKey, decapsulationKey } = kem.keygen(seed);
        expect(kem.checkEncapsulationKey(encapsulationKey)).toBe(true);
        expect(kem.checkDecapsulationKey(decapsulationKey)).toBe(true);
      }),
      { numRuns: 50 },
    );
  });
});

describe('ring arithmetic', () => {
  it('NTT multiplication equals schoolbook multiplication mod X^256 + 1', () => {
    fc.assert(
      fc.property(poly(), poly(), (f, g) => {
        expect(invNtt(multiplyNtts(ntt(f), ntt(g)))).toEqual(schoolbookMultiply(f, g));
      }),
      { numRuns: 100 },
    );
  });

  it('the inverse NTT undoes the NTT', () => {
    fc.assert(
      fc.property(poly(), (f) => {
        expect(invNtt(ntt(f))).toEqual(f);
      }),
      { numRuns: 300 },
    );
  });
});

describe('encoding', () => {
  it('ByteDecode_d inverts ByteEncode_d for d-bit values', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 11 }).chain((d) => fc.tuple(fc.constant(d), poly(2 ** d - 1))),
        ([d, f]) => {
          expect(byteDecode(byteEncode(f, d), d)).toEqual(f);
        },
      ),
    );
  });

  it('Decompress_d(Compress_d(x)) is within round(q / 2^(d+1)) of x', () => {
    fc.assert(
      fc.property(fc.constantFrom(1, 4, 5, 10, 11), poly(), (d, f) => {
        const back = decompress(compress(f, d), d);
        const bound = Math.round(Q / 2 ** (d + 1));
        for (let i = 0; i < N; i++) expect(Math.abs(centered((back[i]! - f[i]! + Q) % Q))).toBeLessThanOrEqual(bound);
      }),
    );
  });

  it('Compress_d(Decompress_d(y)) == y: decompression loses nothing', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(1, 4, 5, 10, 11).chain((d) => fc.tuple(fc.constant(d), poly(2 ** d - 1))),
        ([d, y]) => {
          expect(compress(decompress(y, d), d)).toEqual(y);
        },
      ),
    );
  });
});
