// ML-KEM, FIPS 203 sections 6 and 7 (Algorithms 16 to 21): K-PKE wrapped in
// a Fujisaki-Okamoto transform with implicit rejection, plus the input
// checks section 7 requires before keys and ciphertexts from outside are used.

import { byteDecodeVector, byteEncodeVector } from './encoding.ts';
import { G, kpkeDecrypt, kpkeEncrypt, kpkeKeyGen, type DecryptTrace, type EncryptTrace, type KeyGenTrace } from './kpke.ts';
import { ML_KEM_1024, ML_KEM_512, ML_KEM_768, type ParameterSet } from './params.ts';
import { sha3_256, shake256 } from './sha3.ts';

/** H(s) = SHA3-256(s) (FIPS 203 eq. 4.4). */
export const H = (...parts: Uint8Array[]): Uint8Array => sha3_256(...parts);

/** J(s) = SHAKE256(s), 32 bytes (FIPS 203 eq. 4.4). */
export function J(...parts: Uint8Array[]): Uint8Array {
  const xof = shake256();
  for (const p of parts) xof.absorb(p);
  return xof.squeeze(32);
}

/** Thrown when a key or ciphertext fails the checks of FIPS 203 section 7. */
export class MlKemInputError extends Error {
  override name = 'MlKemInputError';
}

export interface KeyPair {
  /** The public key, 384k + 32 bytes. */
  encapsulationKey: Uint8Array;
  /** The private key, 768k + 96 bytes. It contains a copy of the public key. */
  decapsulationKey: Uint8Array;
}

export interface Encapsulation {
  /** The 32-byte shared secret. */
  sharedSecret: Uint8Array;
  /** Send this to the holder of the decapsulation key. */
  ciphertext: Uint8Array;
}

/** Constant-time in intent: no early exit on the first differing byte. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** out = equal ? a : b, selected with a mask rather than a branch. */
function select(equal: boolean, a: Uint8Array, b: Uint8Array): Uint8Array {
  const mask = -Number(equal) & 0xff; // 0xff when equal, 0 when not
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i]! & mask) | (b[i]! & ~mask);
  return out;
}

function expectLength(what: string, bytes: Uint8Array, length: number): void {
  if (!(bytes instanceof Uint8Array)) throw new MlKemInputError(`${what} must be a Uint8Array`);
  if (bytes.length !== length) throw new MlKemInputError(`${what} must be ${length} bytes, got ${bytes.length}`);
}

interface CryptoLike {
  getRandomValues<T extends ArrayBufferView>(array: T): T;
}

function randomBytes(length: number): Uint8Array {
  const crypto = (globalThis as { crypto?: CryptoLike }).crypto;
  if (!crypto?.getRandomValues) throw new Error('latticework: no crypto.getRandomValues in this environment');
  return crypto.getRandomValues(new Uint8Array(length));
}

export interface DecapsulateTrace {
  decrypt?: DecryptTrace;
  /** The message K-PKE decryption recovered. */
  mPrime?: Uint8Array;
  /** The shared secret and re-encryption randomness derived from m'. */
  kPrime?: Uint8Array;
  rPrime?: Uint8Array;
  /** The implicit-rejection key J(z || c). */
  kBar?: Uint8Array;
  reencrypt?: EncryptTrace;
  /** The ciphertext re-encrypted from m'. */
  cPrime?: Uint8Array;
  /** Whether c' equals c, so K' was kept rather than replaced by K-bar. */
  accepted?: boolean;
}

export interface EncapsulateTrace {
  /** H(ek), which binds the shared secret to the public key. */
  hEk?: Uint8Array;
  r?: Uint8Array;
  encrypt?: EncryptTrace;
}

/** One ML-KEM parameter set's operations. */
export class MlKem {
  readonly params: ParameterSet;

  constructor(params: ParameterSet) {
    this.params = params;
  }

  // ------------------------------------------------------------- internal

  /**
   * ML-KEM.KeyGen_internal (Algorithm 16). Deterministic: d and z are the
   * two 32-byte seeds. dk = dk_PKE || ek || H(ek) || z.
   */
  keygenInternal(d: Uint8Array, z: Uint8Array, trace?: KeyGenTrace): KeyPair {
    expectLength('d', d, 32);
    expectLength('z', z, 32);
    const { k } = this.params;
    const { ek, dk: dkPke } = kpkeKeyGen(this.params, d, trace);
    const dk = new Uint8Array(this.params.decapsulationKeyBytes);
    dk.set(dkPke, 0);
    dk.set(ek, 384 * k);
    dk.set(H(ek), 768 * k + 32);
    dk.set(z, 768 * k + 64);
    return { encapsulationKey: ek, decapsulationKey: dk };
  }

  /** ML-KEM.Encaps_internal (Algorithm 17). Deterministic: m is the 32-byte message. No input checks. */
  encapsulateInternal(ek: Uint8Array, m: Uint8Array, trace?: EncapsulateTrace): Encapsulation {
    expectLength('m', m, 32);
    const hEk = H(ek);
    const [K, r] = G(m, hEk);
    const encrypt: EncryptTrace | undefined = trace ? {} : undefined;
    const c = kpkeEncrypt(this.params, ek, m, r, encrypt);
    if (trace) Object.assign(trace, { hEk, r: r.slice(), encrypt });
    return { sharedSecret: K.slice(), ciphertext: c };
  }

  /**
   * ML-KEM.Decaps_internal (Algorithm 18). No input checks. Always returns
   * a key: if the ciphertext does not re-encrypt to itself, the key is
   * J(z || c), which the sender cannot know.
   */
  decapsulateInternal(dk: Uint8Array, c: Uint8Array, trace?: DecapsulateTrace): Uint8Array {
    const { k } = this.params;
    const dkPke = dk.subarray(0, 384 * k);
    const ekPke = dk.subarray(384 * k, 768 * k + 32);
    const h = dk.subarray(768 * k + 32, 768 * k + 64);
    const z = dk.subarray(768 * k + 64, 768 * k + 96);

    const decrypt: DecryptTrace | undefined = trace ? {} : undefined;
    const mPrime = kpkeDecrypt(this.params, dkPke, c, decrypt);
    const [kPrime, rPrime] = G(mPrime, h);
    const kBar = J(z, c);
    const reencrypt: EncryptTrace | undefined = trace ? {} : undefined;
    const cPrime = kpkeEncrypt(this.params, ekPke, mPrime, rPrime, reencrypt);
    const accepted = bytesEqual(c, cPrime);
    const key = select(accepted, kPrime, kBar);

    if (trace) {
      Object.assign(trace, { decrypt, mPrime, kPrime: kPrime.slice(), rPrime: rPrime.slice(), kBar, reencrypt, cPrime, accepted });
    }
    return key;
  }

  // ---------------------------------------------------------------- checks

  /**
   * The encapsulation key check of section 7.2: the right length, and every
   * 12-bit coefficient below q (ByteEncode_12(ByteDecode_12(ek)) == ek).
   */
  checkEncapsulationKey(ek: Uint8Array): boolean {
    if (!(ek instanceof Uint8Array) || ek.length !== this.params.encapsulationKeyBytes) return false;
    const k = this.params.k;
    const t = ek.subarray(0, 384 * k);
    return bytesEqual(byteEncodeVector(byteDecodeVector(t, 12, k), 12), t);
  }

  /**
   * The decapsulation key check of section 7.3: the right length, and the
   * stored H(ek) matches the stored ek. It does not prove the two halves of
   * the key belong together; nothing cheap can.
   */
  checkDecapsulationKey(dk: Uint8Array): boolean {
    if (!(dk instanceof Uint8Array) || dk.length !== this.params.decapsulationKeyBytes) return false;
    const k = this.params.k;
    return bytesEqual(H(dk.subarray(384 * k, 768 * k + 32)), dk.subarray(768 * k + 32, 768 * k + 64));
  }

  // ---------------------------------------------------------------- public

  /**
   * ML-KEM.KeyGen (Algorithm 19). With no argument the seeds come from
   * crypto.getRandomValues. A 64-byte `seed` (d || z) makes it
   * deterministic, which is also how the key can be stored compactly.
   */
  keygen(seed?: Uint8Array): KeyPair {
    const s = seed ?? randomBytes(64);
    expectLength('seed', s, 64);
    return this.keygenInternal(s.subarray(0, 32), s.subarray(32, 64));
  }

  /** ML-KEM.Encaps (Algorithm 20), with the section 7.2 key check. */
  encapsulate(encapsulationKey: Uint8Array): Encapsulation {
    expectLength('encapsulation key', encapsulationKey, this.params.encapsulationKeyBytes);
    if (!this.checkEncapsulationKey(encapsulationKey)) {
      throw new MlKemInputError('encapsulation key has a coefficient that is not reduced mod q');
    }
    return this.encapsulateInternal(encapsulationKey, randomBytes(32));
  }

  /** ML-KEM.Decaps (Algorithm 21), with the section 7.3 checks. */
  decapsulate(decapsulationKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    expectLength('ciphertext', ciphertext, this.params.ciphertextBytes);
    expectLength('decapsulation key', decapsulationKey, this.params.decapsulationKeyBytes);
    if (!this.checkDecapsulationKey(decapsulationKey)) {
      throw new MlKemInputError('decapsulation key hash check failed: H(ek) does not match the stored value');
    }
    return this.decapsulateInternal(decapsulationKey, ciphertext);
  }
}

export const mlKem512 = new MlKem(ML_KEM_512);
export const mlKem768 = new MlKem(ML_KEM_768);
export const mlKem1024 = new MlKem(ML_KEM_1024);
