// Keccak-f[1600] and the sponge construction, FIPS 202.
//
// The state is 25 lanes of 64 bits. JavaScript has no fast 64-bit integers
// (BigInt is far too slow for this), so every lane is kept as two 32-bit
// halves in a Uint32Array: lane i lives at [2i] (low word) and [2i + 1]
// (high word). Lane (x, y) is lane index x + 5y, as in the standard.
//
// The rotation offsets and round constants are not typed in from a table:
// they are generated the way FIPS 202 defines them (Algorithm 2 for rho,
// Algorithm 5 for rc), and a test compares the result with the published
// values.

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

// rho and pi fused: lane (x, y) is rotated by r[x, y] and moved to
// (y, 2x + 3y mod 5). Precompute the destination and the rotation for each
// source lane so the round function is a flat loop.
const PI_DEST = new Uint8Array(25);
const ROT_LO_SHIFT = new Uint8Array(25);
const ROT_SWAP = new Uint8Array(25); // 1 when the rotation is 32 or more
for (let x = 0; x < 5; x++) {
  for (let y = 0; y < 5; y++) {
    const src = x + 5 * y;
    PI_DEST[src] = y + 5 * ((2 * x + 3 * y) % 5);
    const n = RHO_OFFSETS[src]!;
    ROT_SWAP[src] = n >= 32 ? 1 : 0;
    ROT_LO_SHIFT[src] = n % 32;
  }
}

const C = new Uint32Array(10);
const B = new Uint32Array(50);

/** Keccak-f[1600]: 24 rounds of theta, rho, pi, chi and iota, in place. */
export function keccakF1600(s: Uint32Array): void {
  for (let round = 0; round < 24; round++) {
    // theta: XOR each lane with the parities of two neighbouring columns.
    for (let x = 0; x < 5; x++) {
      const i = 2 * x;
      C[i] = s[i]! ^ s[i + 10]! ^ s[i + 20]! ^ s[i + 30]! ^ s[i + 40]!;
      C[i + 1] = s[i + 1]! ^ s[i + 11]! ^ s[i + 21]! ^ s[i + 31]! ^ s[i + 41]!;
    }
    for (let x = 0; x < 5; x++) {
      const prev = 2 * ((x + 4) % 5);
      const next = 2 * ((x + 1) % 5);
      // D[x] = C[x - 1] ^ rot(C[x + 1], 1)
      const nlo = C[next]!;
      const nhi = C[next + 1]!;
      const dlo = C[prev]! ^ ((nlo << 1) | (nhi >>> 31));
      const dhi = C[prev + 1]! ^ ((nhi << 1) | (nlo >>> 31));
      for (let y = 0; y < 50; y += 10) {
        s[y + 2 * x]! ^= dlo;
        s[y + 2 * x + 1]! ^= dhi;
      }
    }

    // rho + pi
    for (let src = 0; src < 25; src++) {
      let lo = s[2 * src]!;
      let hi = s[2 * src + 1]!;
      if (ROT_SWAP[src]) {
        const t = lo;
        lo = hi;
        hi = t;
      }
      const n = ROT_LO_SHIFT[src]!;
      const dest = 2 * PI_DEST[src]!;
      if (n === 0) {
        B[dest] = lo;
        B[dest + 1] = hi;
      } else {
        B[dest] = (lo << n) | (hi >>> (32 - n));
        B[dest + 1] = (hi << n) | (lo >>> (32 - n));
      }
    }

    // chi: the only non-linear step. a ^= ~b & c along each row.
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 5; x++) {
        const a = y + 2 * x;
        const b = y + 2 * ((x + 1) % 5);
        const c = y + 2 * ((x + 2) % 5);
        s[a] = B[a]! ^ (~B[b]! & B[c]!);
        s[a + 1] = B[a + 1]! ^ (~B[b + 1]! & B[c + 1]!);
      }
    }

    // iota
    s[0]! ^= ROUND_CONSTANTS[2 * round]!;
    s[1]! ^= ROUND_CONSTANTS[2 * round + 1]!;
  }
}

const LITTLE_ENDIAN = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1;

/**
 * A Keccak sponge with a byte-granular rate. Absorb, then squeeze; once
 * squeezing has started, absorbing again throws.
 *
 * `suffix` is the domain-separation bits plus the first bit of pad10*1,
 * packed least significant bit first: 0x06 for SHA-3 ("01" then "1") and
 * 0x1f for SHAKE ("1111" then "1").
 */
export class KeccakSponge {
  readonly rate: number;
  private readonly suffix: number;
  private readonly state = new Uint32Array(50);
  private readonly bytes: Uint8Array;
  private pos = 0;
  private squeezing = false;

  constructor(rate: number, suffix: number) {
    if (!LITTLE_ENDIAN) throw new Error('latticework: big-endian platforms are not supported');
    if (rate <= 0 || rate >= 200) throw new RangeError(`rate must be in 1..199 bytes, got ${rate}`);
    this.rate = rate;
    this.suffix = suffix;
    this.bytes = new Uint8Array(this.state.buffer);
  }

  absorb(data: Uint8Array): this {
    if (this.squeezing) throw new Error('cannot absorb after squeezing has started');
    const { bytes, rate } = this;
    let pos = this.pos;
    for (let i = 0; i < data.length; i++) {
      bytes[pos++]! ^= data[i]!;
      if (pos === rate) {
        keccakF1600(this.state);
        pos = 0;
      }
    }
    this.pos = pos;
    return this;
  }

  /**
   * Absorb a final partial byte of `bits` bits (1 to 7) and pad. The message
   * bits are the low `bits` bits of `value`, least significant first, which
   * is the bit order FIPS 202 uses inside a byte. Only needed for
   * bit-oriented test vectors; the KEM never calls it.
   */
  absorbFinalBits(value: number, bits: number): this {
    if (this.squeezing) throw new Error('cannot absorb after squeezing has started');
    if (!Number.isInteger(bits) || bits < 1 || bits > 7) throw new RangeError(`bits must be 1..7, got ${bits}`);
    this.pad(value & ((1 << bits) - 1), bits);
    return this;
  }

  private pad(partial: number, partialBits: number): void {
    const { bytes, rate } = this;
    const blockBits = rate * 8;
    // The message's last partial byte, then the suffix bit by bit (it can
    // run into the next byte, or past the end of the block), then the
    // closing 1 of pad10*1 on the last bit of a block. If the suffix used up
    // the block's last bit, that closing 1 needs a block of its own.
    bytes[this.pos]! ^= partial;
    let bit = this.pos * 8 + partialBits;
    for (let s = this.suffix; s !== 0; s >>>= 1) {
      if (bit === blockBits) {
        keccakF1600(this.state);
        bit = 0;
      }
      if (s & 1) bytes[bit >>> 3]! ^= 1 << (bit & 7);
      bit++;
    }
    if (bit === blockBits) keccakF1600(this.state);
    bytes[rate - 1]! ^= 0x80;
    keccakF1600(this.state);
    this.pos = 0;
    this.squeezing = true;
  }

  /** Write the next `out.length` bytes of output into `out`. */
  squeezeInto(out: Uint8Array): Uint8Array {
    if (!this.squeezing) this.pad(0, 0);
    const { bytes, rate } = this;
    let pos = this.pos;
    for (let i = 0; i < out.length; i++) {
      if (pos === rate) {
        keccakF1600(this.state);
        pos = 0;
      }
      out[i] = bytes[pos++]!;
    }
    this.pos = pos;
    return out;
  }

  squeeze(length: number): Uint8Array {
    return this.squeezeInto(new Uint8Array(length));
  }
}
