// Loading NIST ACVP-Server vector files (the internalProjection.json flavour,
// which carries inputs and expected outputs together). The files are fetched
// and hash-checked by scripts/fetch-vectors.mjs, which vitest runs first.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export interface AcvpFile<G> {
  vsId: number;
  algorithm: string;
  mode?: string;
  revision: string;
  testGroups: G[];
}

export function loadVectors<G>(name: string): AcvpFile<G> {
  const path = fileURLToPath(new URL(`../../../../vectors/${name}/internalProjection.json`, import.meta.url));
  return JSON.parse(readFileSync(path, 'utf8')) as AcvpFile<G>;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`odd-length hex string (${hex.length})`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s.toUpperCase();
}
