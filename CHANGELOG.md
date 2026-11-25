# Changelog

## 0.1.0

The first release.

- ML-KEM-512, ML-KEM-768 and ML-KEM-1024 (FIPS 203): key generation, encapsulation, decapsulation with implicit rejection, and the section 7 input checks. Deterministic `*Internal` entry points take an optional trace of intermediate values.
- Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128 and SHAKE256 (FIPS 202), with a readable reference permutation and a generated unrolled one.
- Tested against NIST ACVP vectors: 435 for ML-KEM, 2,382 SHA-3/SHAKE AFT vectors and two Monte Carlo tests. Also differential tests against @noble/post-quantum and @noble/hashes, and property tests.
- An explainer at https://autumntrace.github.io/latticework/ that runs one exchange and draws it step by step.
- A benchmark against @noble/post-quantum.
