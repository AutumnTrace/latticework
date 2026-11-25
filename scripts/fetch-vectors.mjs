// Downloads the NIST ACVP test vectors the tests run against, from a pinned
// commit of https://github.com/usnistgov/ACVP-Server, and checks each file
// against a SHA-256 recorded here. Files already present with the right hash
// are left alone, so this is cheap to run before every test.
//
//   node scripts/fetch-vectors.mjs
//
// The vectors are produced by NIST, a US government agency, and are not
// subject to copyright in the United States. They are not committed to this
// repository only because they are about 8 MB of JSON.
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

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const VECTOR_DIR = join(repo, 'vectors');

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export async function fetchVectors({ log = console.log } = {}) {
  for (const [name, expected] of Object.entries(VECTOR_FILES)) {
    const file = join(VECTOR_DIR, name, 'internalProjection.json');
    if (existsSync(file) && sha256(readFileSync(file)) === expected) continue;
    const url = `https://raw.githubusercontent.com/usnistgov/ACVP-Server/${ACVP_COMMIT}/gen-val/json-files/${name}/internalProjection.json`;
    log(`fetching ${name}`);
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    const actual = sha256(bytes);
    if (actual !== expected) throw new Error(`${name}: SHA-256 is ${actual}, expected ${expected}`);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, bytes);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await fetchVectors();
  console.log(`vectors ready in ${VECTOR_DIR}`);
}
