// Throughput of keygen, encaps and decaps for each parameter set, against
// @noble/post-quantum, on whatever machine runs it.
//
//   npm run bench                 prints a table
//   npm run bench -- --json       also writes bench/results.json
//
// Each pair of measurements (latticework and noble doing the same thing)
// runs in alternating batches after a warm-up, about a second each in
// total, and reports the median batch rate of each. Alternating means both
// see the same machine: if something else wakes up mid-run, it slows both.
import { sha3_256 as nobleSha3_256, shake128 as nobleShake128 } from '@noble/hashes/sha3.js';
import { ml_kem1024, ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { writeFileSync } from 'node:fs';
import { arch, cpus, platform, release, totalmem } from 'node:os';
import { mlKem1024, mlKem512, mlKem768, type MlKem } from '../src/index.ts';
import { sha3_256, shake128 } from '../src/sha3.ts';

interface Result {
  name: string;
  opsPerSec: number;
  usPerOp: number;
}

const BATCHES = 15;
const TARGET_MS = 1000;

function batchSize(fn: () => unknown): number {
  // Warm up and find a batch size that takes about TARGET_MS / BATCHES.
  let n = 1;
  for (;;) {
    const t0 = performance.now();
    for (let i = 0; i < n; i++) fn();
    const dt = performance.now() - t0;
    if (dt > TARGET_MS / BATCHES / 2) return Math.max(1, Math.round((n * (TARGET_MS / BATCHES)) / dt));
    n *= 2;
  }
}

function median(xs: number[]): number {
  const s = xs.toSorted((a, b) => a - b);
  return s[Math.floor(s.length / 2)]!;
}

function result(name: string, rates: number[]): Result {
  const opsPerSec = median(rates);
  return { name, opsPerSec, usPerOp: 1e6 / opsPerSec };
}

/** Measure fns side by side, alternating batches. */
function measure(name: string, ...fns: (() => unknown)[]): Result[] {
  const sizes = fns.map(batchSize);
  const rates: number[][] = fns.map(() => []);
  for (let b = 0; b < BATCHES; b++) {
    fns.forEach((fn, k) => {
      const n = sizes[k]!;
      const t0 = performance.now();
      for (let i = 0; i < n; i++) fn();
      rates[k]!.push((n * 1000) / (performance.now() - t0));
    });
  }
  return rates.map((r) => result(name, r));
}

const seed = new Uint8Array(64).map((_, i) => i * 7);
const msg = new Uint8Array(32).map((_, i) => 255 - i);

const kems: [MlKem, typeof ml_kem512][] = [
  [mlKem512, ml_kem512],
  [mlKem768, ml_kem768],
  [mlKem1024, ml_kem1024],
];

const results: Record<string, { latticework: Result; noble: Result }> = {};
for (const [ours, noble] of kems) {
  const { encapsulationKey: ek, decapsulationKey: dk } = ours.keygen(seed);
  const { ciphertext: c } = ours.encapsulateInternal(ek, msg);
  const name = ours.params.name;
  const pairs: [string, () => unknown, () => unknown][] = [
    ['keygen', () => ours.keygen(seed), () => noble.keygen(seed)],
    ['encaps', () => ours.encapsulate(ek), () => noble.encapsulate(ek)],
    ['decaps', () => ours.decapsulate(dk, c), () => noble.decapsulate(c, dk)],
  ];
  for (const [op, a, b] of pairs) {
    const [latticework, nobleResult] = measure(`${name} ${op}`, a, b);
    results[`${name} ${op}`] = { latticework: latticework!, noble: nobleResult! };
  }
}

const MB = new Uint8Array(1 << 20);
const [sha3, nobleSha3] = measure(
  'SHA3-256, 1 MiB',
  () => sha3_256(MB),
  () => nobleSha3_256(MB),
);
const [shake, nobleShake] = measure(
  'SHAKE128, 1 MiB out',
  () =>
    shake128()
      .absorb(msg)
      .squeeze(1 << 20),
  () => nobleShake128(msg, { dkLen: 1 << 20 }),
);
const hashing = { 'SHA3-256, 1 MiB in': { latticework: sha3!, noble: nobleSha3! }, 'SHAKE128, 1 MiB out': { latticework: shake!, noble: nobleShake! } };

const cpu = cpus()[0]?.model.trim() ?? 'unknown CPU';
const machine = {
  cpu,
  cores: cpus().length,
  memoryGiB: Math.round(totalmem() / 2 ** 30),
  os: `${platform()} ${release()} ${arch()}`,
  node: process.version,
  v8: process.versions.v8,
};

const pad = (s: string, n: number) => s.padEnd(n);
const num = (x: number) => Math.round(x).toLocaleString('en-US');
console.log(`${machine.cpu}, ${machine.os}, Node ${machine.node}\n`);
console.log(`| operation | latticework ops/s | noble ops/s | latticework / noble |`);
console.log(`|---|---:|---:|---:|`);
for (const [name, r] of Object.entries(results)) {
  console.log(
    `| ${pad(name, 20)} | ${num(r.latticework.opsPerSec)} | ${num(r.noble.opsPerSec)} | ${(r.latticework.opsPerSec / r.noble.opsPerSec).toFixed(2)}x |`,
  );
}
console.log('');
const mbs = (r: Result) => ((r.opsPerSec * (1 << 20)) / 1e6).toFixed(0);
for (const [name, r] of Object.entries(hashing)) console.log(`${name}: latticework ${mbs(r.latticework)} MB/s, noble ${mbs(r.noble)} MB/s`);

if (process.argv.includes('--json')) {
  const out = new URL('./results.json', import.meta.url);
  writeFileSync(out, JSON.stringify({ date: new Date().toISOString().slice(0, 10), machine, kem: results, hashing }, null, 2) + '\n');
  console.log(`\nwrote ${out.pathname}`);
}
