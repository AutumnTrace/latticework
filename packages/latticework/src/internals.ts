// The building blocks, for tests, the explainer, and anyone reading along
// with FIPS 203. Not a stable API: names follow the standard, not semver.
export { KeccakSponge, keccakF1600, RHO_OFFSETS, ROUND_CONSTANTS } from './keccak.ts';
export { concat, keccakBits, sha3_256, sha3_512, shake128, shake256, type Sha3Function, type Xof } from './sha3.ts';
export { N, Q, ZETA } from './params.ts';
export {
  addInPlace,
  bitRev7,
  centered,
  GAMMAS,
  invNtt,
  invNttInPlace,
  multiplyNtts,
  multiplyNttsAcc,
  N_INV_128,
  newPoly,
  ntt,
  nttInPlace,
  schoolbookMultiply,
  sub,
  ZETAS,
  type Poly,
} from './ntt.ts';
export { byteDecode, byteDecodeVector, byteEncode, byteEncodeVector, compress, decompress } from './encoding.ts';
export { prf, sampleNtt, samplePolyCbd, type SampleNttStats } from './sampling.ts';
export { expandMatrix, G, kpkeDecrypt, kpkeEncrypt, kpkeKeyGen, type DecryptTrace, type EncryptTrace, type KeyGenTrace } from './kpke.ts';
export { H, J } from './mlkem.ts';
