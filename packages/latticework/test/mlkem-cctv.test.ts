// ML-KEM against the C2SP/CCTV vectors (https://c2sp.org/CCTV/ML-KEM), which
// target failure modes the ACVP sets reach only by luck. The files are
// fetched and hash-checked by scripts/fetch-vectors.mjs, which vitest runs
// first; the accumulated hashes are quoted from CCTV's README at the same
// pinned commit.
//
// The unlucky-sampling and accumulated vectors were made for the FIPS 203
// draft (ipd). It derived (rho, sigma) = G(d) in K-PKE.KeyGen, where the
// final standard hashes G(d || k). Nothing else differs: those tests build
// their keys with draftKeygen below, which swaps only that step and runs the
// rest of the real key generation, and use the library's own encapsulation
// and decapsulation unchanged.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { G, kpkeKeyGenFromSeeds } from '../src/kpke.ts';
import { H, J } from '../src/mlkem.ts';
import { MlKem, MlKemInputError, mlKem1024, mlKem512, mlKem768, type KeyPair } from '../src/index.ts';
import { sampleNtt, type SampleNttStats } from '../src/sampling.ts';
import { shake128 } from '../src/sha3.ts';
import { fromHex, toHex } from './helpers/acvp.ts';

const KEMS: [string, MlKem][] = [
  ['ML-KEM-512', mlKem512],
  ['ML-KEM-768', mlKem768],
  ['ML-KEM-1024', mlKem1024],
];

function cctvFile(path: string): Buffer {
  return readFileSync(fileURLToPath(new URL(`../../../vectors/cctv/${path}`, import.meta.url)));
}

/** `name = hex` lines; one vector per file. */
function readRecord(path: string): Record<string, string> {
  const record: Record<string, string> = {};
  for (const line of cctvFile(path).toString('utf8').split('\n')) {
    const m = /^(\w+) = ([0-9a-f]+)\s*$/.exec(line);
    if (m) record[m[1]!] = m[2]!.toUpperCase();
  }
  return record;
}

/** ML-KEM.KeyGen_internal as the FIPS 203 draft had it: (rho, sigma) = G(d), without k. */
function draftKeygen(kem: MlKem, d: Uint8Array, z: Uint8Array): KeyPair {
  const [rho, sigma] = G(d);
  const { ek, dk: dkPke } = kpkeKeyGenFromSeeds(kem.params, rho, sigma);
  const dk = new Uint8Array(kem.params.decapsulationKeyBytes);
  dk.set(dkPke, 0);
  dk.set(ek, dkPke.length);
  dk.set(H(ek), dkPke.length + ek.length);
  dk.set(z, dkPke.length + ek.length + 32);
  return { encapsulationKey: ek, decapsulationKey: dk };
}

describe('CCTV strcmp', () => {
  // Each ciphertext differs from its re-encryption only after a zero byte,
  // so a comparison that stops at the first 0x00 would accept it.
  for (const [name, kem] of KEMS) {
    it(`${name}: the ciphertext is rejected, and the key is J(z || c)`, () => {
      const v = readRecord(`strcmp/${name}.txt`);
      const dk = fromHex(v.dk!);
      const c = fromHex(v.c!);
      expect(toHex(kem.decapsulate(dk, c))).toBe(v.K);
      expect(toHex(J(dk.subarray(dk.length - 32), c)), 'the expected key is the rejection key').toBe(v.K);
    });
  }
});

describe('CCTV unlucky SampleNTT', () => {
  for (const [name, kem] of KEMS) {
    it(`${name}: a key whose matrix entry needs more than 575 bytes of SHAKE128`, () => {
      const v = readRecord(`unluckysample/${name}.txt`);
      const d = fromHex(v.d!);
      const z = fromHex(v.z!);
      const { encapsulationKey: ek, decapsulationKey: dk } = draftKeygen(kem, d, z);
      expect(toHex(ek), 'ek').toBe(v.ek);
      expect(toHex(dk), 'dk').toBe(v.dk);
      // The same seed under the final standard gives a different key.
      expect(toHex(kem.keygenInternal(d, z).encapsulationKey)).not.toBe(v.ek);

      // Encapsulation expands A-hat from the rho in ek: this is where the
      // long SampleNTT read happens, in the final algorithm unchanged.
      const { sharedSecret, ciphertext } = kem.encapsulateInternal(ek, fromHex(v.m!));
      expect(toHex(ciphertext), 'c').toBe(v.c);
      expect(toHex(sharedSecret), 'K').toBe(v.K);
      expect(toHex(kem.decapsulate(dk, ciphertext)), 'decapsulated K').toBe(v.K);

      // Entry (0, 0), SampleNTT(rho || 0 || 0), reads past 575 bytes, which
      // happens by chance with probability about 2^-38.
      const rho = ek.subarray(384 * kem.params.k);
      const stats: SampleNttStats = { candidates: 0, rejected: 0, bytes: 0 };
      sampleNtt(Uint8Array.of(...rho, 0, 0), stats);
      expect(stats.bytes).toBeGreaterThan(575);
    });
  }
});

describe('CCTV modulus', () => {
  // One key per line, each with one unreduced coefficient. Between them they
  // cover every value from q to 2^12 - 1 and every coefficient position.
  for (const [name, kem] of KEMS) {
    it(`${name}: every encapsulation key with an unreduced coefficient is refused`, () => {
      const keys = gunzipSync(cctvFile(`modulus/${name}.txt.gz`))
        .toString('utf8')
        .split('\n')
        .filter(Boolean);
      expect(keys.length).toBeGreaterThan(0);
      for (const [i, hex] of keys.entries()) {
        const ek = fromHex(hex);
        expect(ek.length, `line ${i + 1}`).toBe(kem.params.encapsulationKeyBytes);
        expect(kem.checkEncapsulationKey(ek), `line ${i + 1}`).toBe(false);
        expect(() => kem.encapsulate(ek), `line ${i + 1}`).toThrow(MlKemInputError);
      }
    });
  }
});

describe('CCTV accumulated pq-crystals vectors', () => {
  // The 10,000 tests of pq-crystals' ref/test/test_vectors.c, regenerated from
  // a deterministic RNG and hashed instead of stored. Expected hashes from
  // https://github.com/C2SP/CCTV/blob/b88c4b206254ac543df240097e0f1fcc6a664821/ML-KEM/README.md
  // (the 1,000,000-test hashes there are not run).
  //
  // About a minute of CPU in all, so they run only in `npm run test:full`
  // (vitest --mode full), which is what CI runs. `npm test` skips them.
  const FULL = process.env.MODE === 'full';
  const EXPECTED: Record<string, string> = {
    'ML-KEM-512': '845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4',
    'ML-KEM-768': 'f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3',
    'ML-KEM-1024': '47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543',
  };
  const TESTS = 10_000;

  it('the RNG is SHAKE128 of the empty string', () => {
    expect(toHex(shake128().squeeze(16)).toLowerCase()).toBe('7f9c2ba4e88f827d616045507605853e');
  });

  for (const [name, kem] of KEMS) {
    it.runIf(FULL)(`${name}: 10,000 pseudo-random keygen, encaps and decaps rounds hash to the published value`, { timeout: 300_000 }, () => {
      const rng = shake128();
      const acc = shake128();
      for (let i = 0; i < TESTS; i++) {
        const d = rng.squeeze(32);
        const z = rng.squeeze(32);
        const m = rng.squeeze(32);
        const badCt = rng.squeeze(kem.params.ciphertextBytes);

        const { encapsulationKey: ek, decapsulationKey: dk } = draftKeygen(kem, d, z);
        const { sharedSecret: k, ciphertext: ct } = kem.encapsulateInternal(ek, m);
        if (toHex(kem.decapsulate(dk, ct)) !== toHex(k)) throw new Error(`test ${i}: decapsulation does not recover the shared secret`);
        const kReject = kem.decapsulate(dk, badCt);

        acc.absorb(ek).absorb(dk).absorb(ct).absorb(k).absorb(kReject);
      }
      expect(toHex(acc.squeeze(32)).toLowerCase()).toBe(EXPECTED[name]);
    });
  }
});
