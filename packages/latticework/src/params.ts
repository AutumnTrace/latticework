// The three ML-KEM parameter sets, FIPS 203 Table 2, and the sizes that
// follow from them (Table 3).

/** Polynomials have n = 256 coefficients... */
export const N = 256;
/** ...in Z_q with q = 3329 = 13 * 2^8 + 1, a prime with 256 | q - 1. */
export const Q = 3329;
/** 17 is a primitive 256th root of unity mod q. */
export const ZETA = 17;

export type ParameterSetName = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';

export interface ParameterSet {
  readonly name: ParameterSetName;
  /** Module rank: vectors have k polynomials, the matrix is k x k. */
  readonly k: number;
  /** CBD width for the secret s, the key-generation error e and the encryption randomness y. */
  readonly eta1: number;
  /** CBD width for the encryption errors e1 and e2. */
  readonly eta2: number;
  /** Bits per coefficient of u in the ciphertext. */
  readonly du: number;
  /** Bits per coefficient of v in the ciphertext. */
  readonly dv: number;
  /** NIST security category (1, 3, 5). */
  readonly category: 1 | 3 | 5;
  readonly encapsulationKeyBytes: number;
  readonly decapsulationKeyBytes: number;
  readonly ciphertextBytes: number;
  readonly sharedSecretBytes: 32;
}

function parameterSet(name: ParameterSetName, k: number, eta1: number, eta2: number, du: number, dv: number, category: 1 | 3 | 5): ParameterSet {
  return Object.freeze({
    name,
    k,
    eta1,
    eta2,
    du,
    dv,
    category,
    encapsulationKeyBytes: 384 * k + 32,
    decapsulationKeyBytes: 768 * k + 96,
    ciphertextBytes: 32 * (du * k + dv),
    sharedSecretBytes: 32,
  });
}

export const ML_KEM_512 = parameterSet('ML-KEM-512', 2, 3, 2, 10, 4, 1);
export const ML_KEM_768 = parameterSet('ML-KEM-768', 3, 2, 2, 10, 4, 3);
export const ML_KEM_1024 = parameterSet('ML-KEM-1024', 4, 2, 2, 11, 5, 5);

export const PARAMETER_SETS: readonly ParameterSet[] = [ML_KEM_512, ML_KEM_768, ML_KEM_1024];

export function parameterSetByName(name: string): ParameterSet {
  const p = PARAMETER_SETS.find((s) => s.name === name);
  if (!p) throw new RangeError(`unknown parameter set ${JSON.stringify(name)}`);
  return p;
}
