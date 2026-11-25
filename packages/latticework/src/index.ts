// latticework: ML-KEM (FIPS 203) in TypeScript.
//
//   import { mlKem768 } from '@autumntrace/latticework';
//   const { encapsulationKey, decapsulationKey } = mlKem768.keygen();
//   const { sharedSecret, ciphertext } = mlKem768.encapsulate(encapsulationKey);
//   mlKem768.decapsulate(decapsulationKey, ciphertext); // the same 32 bytes
export {
  MlKem,
  MlKemInputError,
  mlKem1024,
  mlKem512,
  mlKem768,
  type DecapsulateTrace,
  type EncapsulateTrace,
  type Encapsulation,
  type KeyPair,
} from './mlkem.ts';
export { ML_KEM_1024, ML_KEM_512, ML_KEM_768, PARAMETER_SETS, parameterSetByName, type ParameterSet, type ParameterSetName } from './params.ts';
