// ML-KEM against NIST's ACVP vectors: key generation, encapsulation,
// decapsulation (valid and modified ciphertexts), and the two key checks.
import { describe, expect, it } from 'vitest';
import { MlKem, mlKem1024, mlKem512, mlKem768 } from '../src/index.ts';
import { fromHex, loadVectors, toHex } from './helpers/acvp.ts';

const KEMS: Record<string, MlKem> = { 'ML-KEM-512': mlKem512, 'ML-KEM-768': mlKem768, 'ML-KEM-1024': mlKem1024 };

interface KeyGenGroup {
  tgId: number;
  parameterSet: string;
  tests: { tcId: number; d: string; z: string; ek: string; dk: string }[];
}

interface EncapDecapTest {
  tcId: number;
  ek: string;
  dk: string;
  c?: string;
  k?: string;
  m?: string;
  d?: string;
  z?: string;
  testPassed?: boolean;
  reason?: string;
}
interface EncapDecapGroup {
  tgId: number;
  parameterSet: string;
  function: 'encapsulation' | 'decapsulation' | 'encapsulationKeyCheck' | 'decapsulationKeyCheck';
  keyFormat?: 'none' | 'seed' | 'expanded';
  tests: EncapDecapTest[];
}

describe('ACVP ML-KEM-keyGen-FIPS203', () => {
  for (const group of loadVectors<KeyGenGroup>('ML-KEM-keyGen-FIPS203').testGroups) {
    const kem = KEMS[group.parameterSet]!;
    it(`${group.parameterSet}: ${group.tests.length} key pairs from (d, z)`, () => {
      for (const t of group.tests) {
        const { encapsulationKey, decapsulationKey } = kem.keygenInternal(fromHex(t.d), fromHex(t.z));
        expect(toHex(encapsulationKey), `tcId ${t.tcId} ek`).toBe(t.ek);
        expect(toHex(decapsulationKey), `tcId ${t.tcId} dk`).toBe(t.dk);
      }
    });
  }
});

for (const file of ['ML-KEM-encapDecap-FIPS203', 'ML-KEM-encapDecap-FIPS203-tr1']) {
  describe(`ACVP ${file}`, () => {
    for (const group of loadVectors<EncapDecapGroup>(file).testGroups) {
      const kem = KEMS[group.parameterSet]!;
      const format = group.keyFormat && group.keyFormat !== 'none' ? `, ${group.keyFormat} keys` : '';
      const reasons = [...new Set(group.tests.map((t) => t.reason).filter(Boolean))].join(' / ');
      const title = `${group.parameterSet} ${group.function}${format}: ${group.tests.length} vectors${reasons ? ` (${reasons})` : ''}`;

      it(title, () => {
        for (const t of group.tests) {
          const id = `tcId ${t.tcId}`;
          switch (group.function) {
            case 'encapsulation': {
              const { sharedSecret, ciphertext } = kem.encapsulateInternal(fromHex(t.ek), fromHex(t.m!));
              expect(toHex(ciphertext), `${id} c`).toBe(t.c);
              expect(toHex(sharedSecret), `${id} k`).toBe(t.k);
              break;
            }
            case 'decapsulation': {
              let dk = fromHex(t.dk);
              if (group.keyFormat === 'seed') {
                // Seed-format keys: the implementation is handed (d, z) and
                // has to expand them itself.
                dk = kem.keygenInternal(fromHex(t.d!), fromHex(t.z!)).decapsulationKey;
                expect(toHex(dk), `${id} expanded dk`).toBe(t.dk);
              }
              expect(toHex(kem.decapsulate(dk, fromHex(t.c!))), `${id} k (${t.reason})`).toBe(t.k);
              break;
            }
            case 'encapsulationKeyCheck':
              expect(kem.checkEncapsulationKey(fromHex(t.ek)), `${id} (${t.reason})`).toBe(t.testPassed);
              break;
            case 'decapsulationKeyCheck':
              expect(kem.checkDecapsulationKey(fromHex(t.dk)), `${id} (${t.reason})`).toBe(t.testPassed);
              break;
          }
        }
      });
    }
  });
}
