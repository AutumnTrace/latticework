import { describe, expect, it } from 'vitest';
import { RHO_OFFSETS, ROUND_CONSTANTS } from '../src/keccak.ts';
import { keccakBits, sha3_256, sha3_512, shake128, shake256, type Sha3Function } from '../src/sha3.ts';
import { fromHex, loadVectors, toHex } from './helpers/acvp.ts';

const ascii = (s: string) => new TextEncoder().encode(s);

describe('Keccak-f[1600] constants', () => {
  it('generates the rho offsets from FIPS 202 Algorithm 2', () => {
    // Table 2 of FIPS 202, read row by row as x + 5y.
    expect(RHO_OFFSETS).toEqual([
      0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    ]);
  });

  it('generates the iota round constants from the rc LFSR', () => {
    const published = [
      '0000000000000001', '0000000000008082', '800000000000808a', '8000000080008000',
      '000000000000808b', '0000000080000001', '8000000080008081', '8000000000008009',
      '000000000000008a', '0000000000000088', '0000000080008009', '000000008000000a',
      '000000008000808b', '800000000000008b', '8000000000008089', '8000000000008003',
      '8000000000008002', '8000000000000080', '000000000000800a', '800000008000000a',
      '8000000080008081', '8000000000008080', '0000000080000001', '8000000080008008',
    ];
    const generated = Array.from({ length: 24 }, (_, i) =>
      ROUND_CONSTANTS[2 * i + 1]!.toString(16).padStart(8, '0') + ROUND_CONSTANTS[2 * i]!.toString(16).padStart(8, '0'),
    );
    expect(generated).toEqual(published);
  });
});

describe('SHA-3 known answers', () => {
  it('hashes the empty string and "abc"', () => {
    expect(toHex(sha3_256())).toBe('A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A');
    expect(toHex(sha3_256(ascii('abc')))).toBe('3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532');
    expect(toHex(sha3_512(ascii('abc')))).toBe(
      'B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0',
    );
  });

  it('treats several parts the same as their concatenation', () => {
    const whole = ascii('the quick brown fox jumps over the lazy dog');
    expect(sha3_256(whole.subarray(0, 7), whole.subarray(7, 30), whole.subarray(30))).toEqual(sha3_256(whole));
  });

  it('squeezes SHAKE as one continuous stream however it is split', () => {
    const seed = ascii('latticework');
    const once = shake128().absorb(seed).squeeze(1000);
    const xof = shake128().absorb(seed);
    const pieces = [xof.squeeze(1), xof.squeeze(167), xof.squeeze(3), xof.squeeze(500), xof.squeeze(329)];
    expect(Uint8Array.from(pieces.flatMap((p) => [...p]))).toEqual(once);
  });

  it('refuses to absorb after squeezing', () => {
    const xof = shake256().absorb(ascii('x'));
    xof.squeeze(1);
    expect(() => xof.absorb(ascii('y'))).toThrow(/after squeezing/);
  });
});

// ACVP writes a bit string of n bits as hex with the last, partial byte
// left-aligned: its bits sit in the high end of the byte. FIPS 202 (and
// keccakBits) keep them in the low end. These two helpers convert.
function acvpBitsIn(msg: Uint8Array, bits: number): Uint8Array {
  const rest = bits % 8;
  if (rest === 0) return msg;
  const out = msg.slice();
  const last = Math.floor(bits / 8);
  out[last] = out[last]! >> (8 - rest);
  return out;
}

function acvpBitsOut(out: Uint8Array, bits: number): Uint8Array {
  const rest = bits % 8;
  if (rest === 0) return out;
  const copy = out.slice();
  copy[copy.length - 1] = (copy[copy.length - 1]! << (8 - rest)) & 0xff;
  return copy;
}

interface HashTest {
  tcId: number;
  msg: string;
  len: number;
  md: string;
  outLen?: number;
  resultsArray?: { md: string }[];
}
interface HashGroup {
  tgId: number;
  testType: 'AFT' | 'MCT' | 'LDT';
  tests: HashTest[];
}

const SUITES: [file: string, fn: Sha3Function][] = [
  ['SHA3-256-2.0', 'sha3-256'],
  ['SHA3-512-2.0', 'sha3-512'],
  ['SHAKE-128-FIPS202', 'shake128'],
  ['SHAKE-256-FIPS202', 'shake256'],
];

for (const [file, fn] of SUITES) {
  const vectors = loadVectors<HashGroup>(file);

  describe(`ACVP ${file}`, () => {
    for (const group of vectors.testGroups) {
      if (group.testType === 'AFT') {
        it(`passes all ${group.tests.length} AFT vectors, bit-oriented lengths included`, () => {
          for (const t of group.tests) {
            const msg = acvpBitsIn(fromHex(t.msg), t.len);
            const out = keccakBits(fn, msg, t.len, t.outLen);
            expect(toHex(acvpBitsOut(out, t.outLen ?? out.length * 8)), `tcId ${t.tcId}`).toBe(t.md);
          }
        });
      } else if (group.testType === 'MCT') {
        const [t] = group.tests;
        it(`passes the Monte Carlo test (100 x 1000 chained hashes)`, () => {
          const hashFn = fn === 'sha3-256' ? sha3_256 : sha3_512;
          let md = fromHex(t!.msg);
          for (const [j, expected] of t!.resultsArray!.entries()) {
            for (let i = 0; i < 1000; i++) md = hashFn(md);
            expect(toHex(md), `outer iteration ${j}`).toBe(expected.md);
          }
        });
      } else {
        // The large-data tests hash a 64 GiB message. Valid, but hours of
        // CPU in JavaScript for no extra coverage of the KEM.
        it.skip(`large-data test (${group.tests.length} x 64 GiB messages)`, () => {});
      }
    }
  });
}
