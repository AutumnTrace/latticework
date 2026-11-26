// Downloads the test vectors the tests run against and checks each file
// against a SHA-256 recorded here. Files already present with the right hash
// are left alone, so this is cheap to run before every test.
//
//   node scripts/fetch-vectors.mjs
//
// - NIST's ACVP vectors, from a pinned commit of
//   https://github.com/usnistgov/ACVP-Server. They are produced by NIST, a US
//   government agency, and are not subject to copyright in the United States.
//   They are not committed to this repository only because they are about
//   8 MB of JSON.
// - The C2SP/CCTV ML-KEM vectors, from a pinned commit of
//   https://github.com/C2SP/CCTV (CC0 1.0): ciphertexts that a strcmp-style
//   comparison would accept, seeds that make SampleNTT read unusually far,
//   and encapsulation keys with an unreduced coefficient at every position.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ACVP_COMMIT = '975de31eb83d87039ec88934fdc47d8c312b892d'; // RELEASE/v1.1.0.43, 2026-08-12

export const VECTOR_FILES = {
  'ML-KEM-keyGen-FIPS203': 'd7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b',
  'ML-KEM-encapDecap-FIPS203': 'a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f',
  'ML-KEM-encapDecap-FIPS203-tr1': '5e88fbd351dc2915b2ab399f5dffd269e1cdbdd0186103ab0e90b374cf592187',
  'SHA3-256-2.0': 'dba4689436c7e440e61dc517210def3e8e09e50c0e9eff29ea66d89bdd0f2c63',
  'SHA3-512-2.0': 'b0521468a178f7fd362d63319aa69b708885d08f0c71cee99ac70729f5bdf64b',
  'SHAKE-128-FIPS202': '1cbebb33db1f7e86ca265f89705dfac95cf90e8e0807b378e088af42cd0ae5db',
  'SHAKE-256-FIPS202': 'a9348d17e009cad62a2baa70160353f5bca936a27116f60dd5811f39b91c6991',
};

export const CCTV_COMMIT = 'b88c4b206254ac543df240097e0f1fcc6a664821'; // 2026-11-01

// Paths under ML-KEM/ in the CCTV repository.
export const CCTV_FILES = {
  'strcmp/ML-KEM-512.txt': '4bc308bf9a7ac41c0e1c6845e9195d4932f66650e09a4ff76ed780e5f606a42f',
  'strcmp/ML-KEM-768.txt': '2b09aa46d8b1c7b9a549a25f009cbd3937b98df177e868d3eb6395930079e4fa',
  'strcmp/ML-KEM-1024.txt': '5059fcb4d5912c37bef560e92608799b576cf785bc20708688f65ffcfca4adfb',
  'unluckysample/ML-KEM-512.txt': '9d4e0ae011978a8f88a49b755ea6996a693428aaea0477c84331580c15b77a9b',
  'unluckysample/ML-KEM-768.txt': 'fede6f787581dc708e5c3337d7e49de33333d23023470668cd0588b65ad0ba90',
  'unluckysample/ML-KEM-1024.txt': '8da6cdb2fb0d4e2223dfa5229ec97d4ded7b93bd8b2202e9a7533850c817b8cd',
  'modulus/ML-KEM-512.txt.gz': '4292314fd44bb211a27ef38273dcac32f602601c2f65b15a69773221227bf298',
  'modulus/ML-KEM-768.txt.gz': '22308df988866e2731c9b79bfa0ce754ea962a77b198436d56bde6481a526af7',
  'modulus/ML-KEM-1024.txt.gz': '5792e788280ecdf5be7bfd2d8b66e18a0f9b9c80f4beb1d801fd27d20e882bf7',
};

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const VECTOR_DIR = join(repo, 'vectors');

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function fetchPinned(name, url, file, expected, log) {
  if (existsSync(file) && sha256(readFileSync(file)) === expected) return;
  log(`fetching ${name}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  const actual = sha256(bytes);
  if (actual !== expected) throw new Error(`${name}: SHA-256 is ${actual}, expected ${expected}`);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, bytes);
}

export async function fetchVectors({ log = console.log } = {}) {
  for (const [name, expected] of Object.entries(VECTOR_FILES)) {
    const url = `https://raw.githubusercontent.com/usnistgov/ACVP-Server/${ACVP_COMMIT}/gen-val/json-files/${name}/internalProjection.json`;
    await fetchPinned(name, url, join(VECTOR_DIR, name, 'internalProjection.json'), expected, log);
  }
  for (const [path, expected] of Object.entries(CCTV_FILES)) {
    const url = `https://raw.githubusercontent.com/C2SP/CCTV/${CCTV_COMMIT}/ML-KEM/${path}`;
    await fetchPinned(`CCTV ${path}`, url, join(VECTOR_DIR, 'cctv', path), expected, log);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await fetchVectors();
  console.log(`vectors ready in ${VECTOR_DIR}`);
}
