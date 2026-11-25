// Differential tests against @noble/post-quantum and @noble/hashes, two
// independent, audited implementations. The NIST vectors pin down a few
// hundred inputs; this throws thousands of random ones at both and compares
// every output byte.
import { sha3_256 as nobleSha3_256, sha3_512 as nobleSha3_512, shake128 as nobleShake128, shake256 as nobleShake256 } from '@noble/hashes/sha3.js';
import { ml_kem1024, ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { mlKem1024, mlKem512, mlKem768 } from '../src/index.ts';
import { sha3_256, sha3_512, shake128, shake256 } from '../src/sha3.ts';

const bytes = (length: number) => fc.uint8Array({ minLength: length, maxLength: length });

const PAIRS = [
  [mlKem512, ml_kem512],
  [mlKem768, ml_kem768],
  [mlKem1024, ml_kem1024],
] as const;

describe.each(PAIRS.map(([ours, noble]) => [ours.params.name, ours, noble] as const))('%s against noble', (_name, ours, noble) => {
  it('derives identical key pairs from the same 64-byte seed', () => {
    fc.assert(
      fc.property(bytes(64), (seed) => {
        const a = ours.keygen(seed);
        const b = noble.keygen(seed);
        expect(a.encapsulationKey).toEqual(b.publicKey);
        expect(a.decapsulationKey).toEqual(b.secretKey);
      }),
      { numRuns: 100 },
    );
  });

  it('encapsulates to the identical ciphertext and secret', () => {
    fc.assert(
      fc.property(bytes(64), bytes(32), (seed, m) => {
        const { publicKey } = noble.keygen(seed);
        const a = ours.encapsulateInternal(publicKey, m);
        const b = noble.encapsulate(publicKey, m);
        expect(a.ciphertext).toEqual(b.cipherText);
        expect(a.sharedSecret).toEqual(b.sharedSecret);
      }),
      { numRuns: 100 },
    );
  });

  it('decapsulates corrupted ciphertexts to the same rejection key', () => {
    fc.assert(
      fc.property(bytes(64), bytes(32), fc.nat(), fc.integer({ min: 1, max: 255 }), (seed, m, where, xor) => {
        const { publicKey, secretKey } = noble.keygen(seed);
        const c = noble.encapsulate(publicKey, m).cipherText;
        c[where % c.length]! ^= xor;
        expect(ours.decapsulate(secretKey, c)).toEqual(noble.decapsulate(c, secretKey));
      }),
      { numRuns: 100 },
    );
  });

  it('decapsulates ciphertexts of random bytes to the same key', () => {
    fc.assert(
      fc.property(bytes(64), bytes(ours.params.ciphertextBytes), (seed, c) => {
        const { secretKey } = noble.keygen(seed);
        expect(ours.decapsulate(secretKey, c)).toEqual(noble.decapsulate(c, secretKey));
      }),
      { numRuns: 50 },
    );
  });

  it('accepts and rejects the same encapsulation keys', () => {
    const k = ours.params.k;
    fc.assert(
      fc.property(bytes(64), fc.nat({ max: 256 * k - 1 }), fc.integer({ min: 3329, max: 4095 }), (seed, index, bad) => {
        const ek = noble.keygen(seed).publicKey;
        // Overwrite one 12-bit coefficient with a value that is not reduced.
        const byte = Math.floor((index * 12) / 8);
        if (index % 2 === 0) {
          ek[byte] = bad & 0xff;
          ek[byte + 1] = (ek[byte + 1]! & 0xf0) | (bad >> 8);
        } else {
          ek[byte] = (ek[byte]! & 0x0f) | ((bad & 0x0f) << 4);
          ek[byte + 1] = bad >> 4;
        }
        expect(ours.checkEncapsulationKey(ek)).toBe(false);
        expect(() => noble.encapsulate(ek)).toThrow();
      }),
      { numRuns: 100 },
    );
  });
});

describe('SHA-3 against @noble/hashes', () => {
  // Lengths around the rates (72, 136, 168 bytes) are where padding bugs live.
  const message = fc.oneof(
    fc.uint8Array({ maxLength: 1200 }),
    fc
      .integer({ min: 0, max: 4 })
      .chain((m) => fc.integer({ min: -2, max: 2 }).chain((d) => fc.uint8Array({ minLength: Math.max(0, 136 * m + d), maxLength: Math.max(0, 136 * m + d) }))),
    fc
      .integer({ min: 0, max: 4 })
      .chain((m) => fc.integer({ min: -2, max: 2 }).chain((d) => fc.uint8Array({ minLength: Math.max(0, 168 * m + d), maxLength: Math.max(0, 168 * m + d) }))),
    fc
      .integer({ min: 0, max: 8 })
      .chain((m) => fc.integer({ min: -2, max: 2 }).chain((d) => fc.uint8Array({ minLength: Math.max(0, 72 * m + d), maxLength: Math.max(0, 72 * m + d) }))),
  );

  it('SHA3-256 and SHA3-512 agree on any message', () => {
    fc.assert(
      fc.property(message, (msg) => {
        expect(sha3_256(msg)).toEqual(nobleSha3_256(msg));
        expect(sha3_512(msg)).toEqual(nobleSha3_512(msg));
      }),
      { numRuns: 500 },
    );
  });

  it('SHAKE128 and SHAKE256 agree on any message and output length, squeezed in any pieces', () => {
    fc.assert(
      fc.property(message, fc.array(fc.integer({ min: 0, max: 400 }), { minLength: 1, maxLength: 6 }), (msg, pieces) => {
        const total = pieces.reduce((a, b) => a + b, 0);
        for (const [ours, theirs] of [
          [shake128, nobleShake128],
          [shake256, nobleShake256],
        ] as const) {
          const xof = ours().absorb(msg);
          const out = new Uint8Array(total);
          let offset = 0;
          for (const p of pieces) {
            out.set(xof.squeeze(p), offset);
            offset += p;
          }
          expect(out).toEqual(theirs(msg, { dkLen: total }));
        }
      }),
      { numRuns: 300 },
    );
  });
});
