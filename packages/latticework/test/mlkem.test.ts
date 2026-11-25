import { describe, expect, it } from 'vitest';
import { MlKemInputError, mlKem1024, mlKem512, mlKem768 } from '../src/index.ts';
import { J } from '../src/mlkem.ts';

const KEMS = [mlKem512, mlKem768, mlKem1024];

describe.each(KEMS.map((kem) => [kem.params.name, kem] as const))('%s', (_name, kem) => {
  const { encapsulationKeyBytes, decapsulationKeyBytes, ciphertextBytes } = kem.params;

  it('agrees on a shared secret', () => {
    const { encapsulationKey, decapsulationKey } = kem.keygen();
    expect(encapsulationKey.length).toBe(encapsulationKeyBytes);
    expect(decapsulationKey.length).toBe(decapsulationKeyBytes);
    const { sharedSecret, ciphertext } = kem.encapsulate(encapsulationKey);
    expect(ciphertext.length).toBe(ciphertextBytes);
    expect(sharedSecret.length).toBe(32);
    expect(kem.decapsulate(decapsulationKey, ciphertext)).toEqual(sharedSecret);
  });

  it('is deterministic given a 64-byte seed', () => {
    const seed = new Uint8Array(64).map((_, i) => i);
    expect(kem.keygen(seed)).toEqual(kem.keygen(seed));
  });

  it('returns J(z || c) for a ciphertext that does not re-encrypt', () => {
    const { encapsulationKey, decapsulationKey } = kem.keygen();
    const { sharedSecret, ciphertext } = kem.encapsulate(encapsulationKey);
    ciphertext[0]! ^= 1;
    const z = decapsulationKey.subarray(decapsulationKeyBytes - 32);
    const key = kem.decapsulate(decapsulationKey, ciphertext);
    expect(key).not.toEqual(sharedSecret);
    expect(key).toEqual(J(z, ciphertext));
  });

  it('rejects keys and ciphertexts of the wrong length', () => {
    const { encapsulationKey, decapsulationKey } = kem.keygen();
    const { ciphertext } = kem.encapsulate(encapsulationKey);
    expect(() => kem.encapsulate(encapsulationKey.subarray(1))).toThrow(MlKemInputError);
    expect(() => kem.decapsulate(decapsulationKey, ciphertext.subarray(1))).toThrow(MlKemInputError);
    expect(() => kem.decapsulate(decapsulationKey.subarray(1), ciphertext)).toThrow(MlKemInputError);
    expect(() => kem.keygen(new Uint8Array(32))).toThrow(MlKemInputError);
  });

  it('rejects an encapsulation key with an unreduced coefficient', () => {
    const { encapsulationKey } = kem.keygen();
    encapsulationKey[0] = 0xff;
    encapsulationKey[1]! |= 0x0f; // first coefficient = 4095, not below q
    expect(kem.checkEncapsulationKey(encapsulationKey)).toBe(false);
    expect(() => kem.encapsulate(encapsulationKey)).toThrow(/not reduced mod q/);
  });

  it('rejects a decapsulation key whose stored H(ek) is wrong', () => {
    const { encapsulationKey, decapsulationKey } = kem.keygen();
    const { ciphertext } = kem.encapsulate(encapsulationKey);
    decapsulationKey[decapsulationKeyBytes - 64]! ^= 1;
    expect(kem.checkDecapsulationKey(decapsulationKey)).toBe(false);
    expect(() => kem.decapsulate(decapsulationKey, ciphertext)).toThrow(/hash check failed/);
  });
});

describe('the three parameter sets', () => {
  it('expand the same seed into different keys: G(d || k) separates them', () => {
    const seed = new Uint8Array(64).fill(7);
    const rhos = KEMS.map((kem) => {
      const ek = kem.keygen(seed).encapsulationKey;
      return Buffer.from(ek.subarray(ek.length - 32)).toString('hex');
    });
    expect(new Set(rhos).size).toBe(3);
  });
});
