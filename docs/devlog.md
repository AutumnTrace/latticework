# Devlog

Notes from building latticework, roughly in order. Mostly the things that didn't work the first time.

## Tooling: TypeScript 7 and linting

The workspace uses TypeScript 7, the native compiler. typescript-eslint 8.74 declares a peer range of `typescript >=4.8.4 <6.1.0`, because it drives the old compiler API, so ESLint with type-aware rules was out. I used oxlint instead (correctness rules as errors, suspicious ones as warnings), and Prettier for formatting. Both run in CI.

One oxlint rule, `no-useless-spread`, flagged `[...ZETAS.slice(0, 8)]` in a test. The spread wasn't useless there: it turned a `Uint16Array` into a plain array so `toEqual` could compare it with an array literal. `Array.from(ZETAS.subarray(0, 8))` says that more clearly anyway.

## SHA-3 against the ACVP vectors: bit order

Keccak came out right on the first known answers (the empty string, "abc"), and the byte-oriented vectors passed. Then the ACVP files turned out to be mostly _bit_-oriented: of SHA3-256's 1,194 AFT vectors, only 151 have a length that is a whole number of bytes. I could have filtered the rest out, but they are cheap to support and they test the padding properly.

The question was which bits of the last hex byte the message bits are. FIPS 202 Appendix B.1 reads bits from the least significant end of each byte. I ran the first 50 bit-oriented vectors under four interpretations:

| Last byte interpreted as | Matched |
| ------------------------ | ------: |
| low n mod 8 bits, as is  |  4 / 50 |
| high bits, shifted down  | 50 / 50 |
| whole byte bit-reversed  | 16 / 50 |
| every byte bit-reversed  |  1 / 50 |

So ACVP left-aligns the final partial byte, and only that byte. Full bytes go in as they are. SHAKE output with a length that isn't a whole number of bytes (196 of SHAKE256's 237 vectors) works the same way in reverse: the last n mod 8 output bits are shifted up to the top of the byte. The library stays with the FIPS 202 convention, and the conversion lives in the test adapter.

## SHA-3: a padding bug only bit-oriented messages can reach

With the bit order sorted out, two vectors still failed: SHA3-256 tcId 1030 and SHA3-512 tcId 521. The SHA3-512 message was 573 bits, which is 71 whole bytes plus 5 bits. With SHA3-512's 72-byte rate, the partial byte is the last byte of the block. The 5 message bits, the 2 domain bits `01` and the first `1` of pad10*1 fill it exactly, all 8 bits. pad10*1 then needs a final `1` on the last bit of the block, and that bit is taken. So the closing `1` has to go in a block of its own, filled with zeros.

My first padding code XORed the suffix into the byte and then XORed `0x80` into the last byte of the block, which here was the same byte. Two ones on the same bit cancel. Whole-byte messages can never hit this: the suffix (`0x06` for SHA-3, `0x1f` for SHAKE) never reaches bit 7. The fix writes the suffix bit by bit, permuting whenever it runs off the end of the block, and adds a block only if the suffix used the block's last bit.

## ML-KEM: the vectors passed first time, so I broke it on purpose

All 30 ML-KEM vector groups passed on the first run. That made me suspicious of the tests rather than pleased with the code. So I swapped `j` and `i` in the matrix seed (ρ ‖ i ‖ j instead of ρ ‖ j ‖ i). The result is a perfectly good KEM, just a different one: 18 of the 30 groups failed, all of keyGen, encapsulation and decapsulation. The 12 key-check groups still passed, correctly, since they don't depend on the matrix at all. Swapped back, all green.

## fast-check and a one-line arrow

A property written as `fc.property(poly(), (f) => expect(invNtt(ntt(f))).toEqual(f))` failed on its first input with "Property failed by returning false", although the assertion itself passed. fast-check treats a property that returns `false` as failed, and the arrow returns whatever the matcher call evaluates to. Wrapping the body in braces, so it returns `undefined`, fixed it. Every property in the repository now uses a block body.

## Speed: it was Keccak

The first benchmark, before any tuning (not interleaved, on a busy machine, so rough):

|                   | latticework |      noble |
| ----------------- | ----------: | ---------: |
| ML-KEM-768 keygen |     3,580/s |    4,010/s |
| ML-KEM-768 encaps |     2,856/s |    3,102/s |
| ML-KEM-768 decaps |     2,592/s |    3,186/s |
| SHA3-256, 1 MiB   |  21–31 MB/s | 33–36 MB/s |

A keygen for ML-KEM-768 runs about 45 Keccak permutations: 27 or so for the nine SampleNTT calls, six PRFs, G, and nine blocks of H(ek). At 4 to 6 µs per permutation, that was most of the 280 µs.

The loop version of the permutation indexes typed arrays everywhere, with `%` in the index arithmetic, a swap for rotations of 32 or more, and two scratch arrays. I wrote a generator that emits the same permutation as straight-line code. Each of the 50 state words is a local variable, and every index, rotation and shift is a literal. That alone took SHA3-256 from 21 to 84 MB/s. Absorbing whole blocks four bytes at a time and squeezing with `set()` instead of byte loops brought it to about 105 MB/s, and ML-KEM-768 keygen to roughly 7,700 to 10,000 per second, depending on the run.

After that, a CPU profile of a keygen/encaps/decaps loop had the permutation at 27%, the NTT and its inverse at about 23%, and allocating polynomials at 6%. Barrett reduction and reusing buffers would help, but at the cost of the code reading like the standard, so I stopped there.

The benchmark used to run each library on its own for a second. Numbers drifted by 20% or more between runs, because other things were running on the machine. It now alternates batches of the two libraries and takes the median of each. The absolute numbers still move between runs, but the ratio barely does.

## Explainer: designing for honesty

I didn't want an explainer whose pictures come from a simplified re-implementation that might quietly differ from the real thing. So the K-PKE and ML-KEM functions take an optional trace object and copy their intermediates into it. The page draws only what those functions recorded, plus values derived from them in a DOM-free `model.ts` that has its own tests.

Where the page states something it can verify, it does, and shows the result in a badge:

- the five noise terms add up to the w that decryption produced (all 256 coefficients, every time so far);
- the NTT path and schoolbook multiplication agree;
- the SampleNTT candidates read independently from SHAKE128 match the matrix.

## Explainer: small things

- The figure headings were styled `text-transform: uppercase`, which turned "noise w − μ" into "NOISE W − M". Greek letters have capitals too. The headings are lowercase now.
- The byte-layout bars put each label inside its segment. H(ek) and z are 32 bytes out of 2,400 in the decapsulation key, about 13 pixels wide. Narrow segments now go unlabelled, with a legend underneath.
- The first NTT diagram drew its butterfly wires at 7% opacity. On a dark background the network was invisible, and only the coefficient columns showed. It's 16% now, and the highlighted cone is drawn on top.
- Element screenshots for the README came out with the sticky settings bar on top of them. The capture script turns the bar's `position: sticky` off before taking pictures.

## Tampering: most flips don't change the message

The fact I enjoyed most came out of the tamper section. For the fixed exchange in the README, all 8,704 single-bit flips of the ciphertext are rejected, as they must be. But in 6,014 of them (69.1%), decryption still recovers _exactly_ the original message. A flip in the low bits of a compressed coefficient moves it by less than the noise margin, and the rounding absorbs it. In c₁ the share is 70% (5,376 of 7,680 bits), in c₂ 62% (638 of 1,024). Implicit rejection doesn't rely on the message changing. It re-encrypts and compares ciphertexts, so every one of those flips still ends with Alice holding K̄ instead of K.
