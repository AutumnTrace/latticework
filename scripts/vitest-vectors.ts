// Vitest global setup: make sure the pinned NIST vectors are on disk before
// any test file runs.
// @ts-expect-error plain .mjs script, no type declarations
import { fetchVectors } from './fetch-vectors.mjs';

export default async function setup(): Promise<void> {
  await fetchVectors();
}
