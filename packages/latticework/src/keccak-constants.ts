// The Keccak-f[1600] constants. They are not typed in from a table: they
// are generated the way FIPS 202 defines them (Algorithm 2 for the rho
// offsets, Algorithm 5 for rc), and a test compares the result with the
// published values.

/** Rotation offsets r[x + 5y] for the rho step (FIPS 202, Algorithm 2). */
export const RHO_OFFSETS: readonly number[] = (() => {
  const r = Array.from({ length: 25 }, () => 0);
  let x = 1;
  let y = 0;
  for (let t = 0; t < 24; t++) {
    r[x + 5 * y] = (((t + 1) * (t + 2)) / 2) % 64;
    [x, y] = [y, (2 * x + 3 * y) % 5];
  }
  return r;
})();

/** rc(t) from FIPS 202 Algorithm 5: one output bit of an 8-bit LFSR. */
function rc(t: number): number {
  if (t % 255 === 0) return 1;
  // R[0..7], R[0] first. Each step prepends a 0 (shifting every bit up one
  // place), XORs the bit that fell off the end into positions 0, 4, 5, 6,
  // and truncates back to 8 bits.
  let r = [1, 0, 0, 0, 0, 0, 0, 0];
  for (let i = 1; i <= t % 255; i++) {
    const shifted = [0, ...r];
    const b8 = shifted[8]!;
    shifted[0]! ^= b8;
    shifted[4]! ^= b8;
    shifted[5]! ^= b8;
    shifted[6]! ^= b8;
    r = shifted.slice(0, 8);
  }
  return r[0]!;
}

/** Round constants for the iota step, as [lo, hi] pairs (FIPS 202, Algorithm 6). */
export const ROUND_CONSTANTS: Uint32Array = (() => {
  const out = new Uint32Array(48);
  for (let round = 0; round < 24; round++) {
    let lo = 0;
    let hi = 0;
    for (let j = 0; j <= 6; j++) {
      if (rc(j + 7 * round) === 0) continue;
      const bit = (1 << j) - 1; // bit positions 0, 1, 3, 7, 15, 31, 63
      if (bit < 32) lo |= 1 << bit;
      else hi |= 1 << (bit - 32);
    }
    out[2 * round] = lo >>> 0;
    out[2 * round + 1] = hi >>> 0;
  }
  return out;
})();
