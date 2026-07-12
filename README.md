# crypto-lab-hash-zoo

## What It Is

Hash Zoo is an interactive side-by-side comparison of three cryptographic hash functions: SHA-256 (Merkle-Damgård construction via `@noble/hashes/sha2`), SHA3-256 (Keccak sponge construction via `@noble/hashes/sha3`), and BLAKE3 (binary tree hash via `@noble/hashes/blake3`). It computes 256-bit digests, measures timing across 100 iterations, and visualizes the avalanche effect — how flipping a single input bit changes roughly half the output bits. The demo also shows SHA-256 Merkle-Damgård padding and SHA-3 rate/capacity parameters to illustrate the structural differences between constructions.

## When to Use It

- **Learning hash function internals.** The avalanche grid and construction diagrams make abstract concepts like sponge absorption and tree-parallel hashing concrete.
- **Comparing performance characteristics.** The timed hash table shows a rough, indicative feel for the relative cost of SHA-256, SHA3-256, and BLAKE3 on identical input in the browser. It is *not* a benchmark — see the timing caveat below.
- **Understanding construction trade-offs.** Side-by-side architecture diagrams clarify why SHA-3 resists length extension while bare Merkle-Damgård does not.
- **Teaching or presenting cryptography.** The live controls (message textarea, bit-position slider) make this suitable for classroom or conference demos.
- **Not for password hashing.** None of these hash functions are memory-hard; use Argon2id or similar KDFs for password storage.
- Do NOT use this as a crypto library — it is a browser teaching demo for comparing hash constructions.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/)**

Type or paste any message into the textarea and click "Hash All Three" to see hex output, average timing, and construction metadata for all three algorithms. Use the bit-position slider in Section B to flip a single bit and watch the 16×16 avalanche grid animate which output bits changed. Click "Padding info" to inspect the SHA-256 padded block and SHA-3 rate/capacity split.

## About the Timings (read before comparing speeds)

The "Time (avg µs)" row is an in-browser average over 100 iterations. It is deliberately labelled *indicative only*, both here and in the app, because single-digit-microsecond measurements taken with `performance.now()` in a JS engine are dominated by noise: JIT warmup, garbage-collection pauses, CPU frequency scaling, and background tab activity all move the numbers around. Do not read the ordering as a definitive speed ranking — on tiny inputs the three functions are all sub-microsecond and the differences are within measurement error. BLAKE3's real speed advantage shows up on large inputs with SIMD and multithreading, which a single-threaded browser loop cannot exercise. For a real comparison, benchmark native builds (for example `b3sum` vs `openssl dgst`) on megabyte-scale inputs. The digests themselves are exact and verified against known-answer test vectors (see below).

## What Can Go Wrong

- **Length extension on bare SHA-256.** Merkle-Damgård hashes expose their internal state as the final digest, allowing an attacker to append data and compute a valid hash without knowing the original message. Use HMAC-SHA256 or switch to SHA-3/BLAKE3.
- **Confusing hash speed with password safety.** SHA-256, SHA3-256, and BLAKE3 are all fast hashes — unsuitable for password storage because an attacker can brute-force billions of guesses per second.
- **Assuming SHA-256 and SHA3-256 are interchangeable.** Despite both producing 256-bit output, their constructions differ fundamentally. Code expecting Merkle-Damgård padding semantics will break if swapped to a sponge hash.
- **Ignoring BLAKE3's tree structure in streaming contexts.** BLAKE3 digests depend on chunk boundaries; streaming implementations must track the tree state correctly or produce wrong hashes.
- **Timing side channels in comparison logic.** Comparing hash digests with early-exit equality checks can leak information about which bytes match; use constant-time comparison in security-critical code.

## Real-World Usage

- **Bitcoin and cryptocurrency.** Bitcoin uses double-SHA-256 for block headers and transaction IDs, relying on Merkle-Damgård's collision resistance.
- **NIST standards and TLS.** SHA-256 is mandated in TLS 1.3 certificate signatures, DNSSEC, and many federal compliance frameworks (FIPS 180-4).
- **Ethereum 2.0 consensus.** The beacon chain uses SHA-256 for its Merkle tree commitments in the proof-of-stake protocol.
- **NIST SHA-3 standard (FIPS 202).** SHA3-256 is standardized as a structural alternative to SHA-2, adopted in protocols requiring sponge-based security guarantees.
- **BLAKE3 file integrity.** The `b3sum` tool and Bao verified streaming use BLAKE3 for fast, parallelizable file checksums and integrity verification.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hash-zoo
cd crypto-lab-hash-zoo
npm install
npm run dev
```

## Tests

The hash wiring is covered by unit tests (Vitest) so a mislabelled or swapped algorithm cannot ship silently:

```bash
npm test        # known-answer vectors + property/round-trip tests
npm run test:a11y   # Playwright + axe-core accessibility gate
```

`src/hasher.test.ts` asserts:

- **Known-answer vectors.** SHA-256, SHA3-256, and BLAKE3 digests of `""` and `"abc"` are checked against the published standard vectors (FIPS 180-4, FIPS 202, BLAKE3 reference). Swapping a source import (for example `sha3` → `sha256`) fails these tests immediately.
- **Distinctness.** The three algorithms produce different digests for the same input.
- **Avalanche ~50%.** Averaged over many single-bit input flips, each algorithm changes close to half of the 256 output bits (asserted within 42–58%).
- **Pure-function correctness.** `popcount` over all 256 byte values, `flipBit` (exactly one bit changed, input not mutated, MSB-first, range/empty guards), `diffBitmap` (bit locations and counts), and `paddingInfo` (SHA-256 Merkle–Damgård `0x80` marker, 512-bit block alignment, big-endian length tail; SHA-3 rate+capacity = 1600).

`npm test` runs only the Vitest unit suite; the Playwright a11y suite in `e2e/` is excluded from it and run separately via `npm run test:a11y`.

## Related Demos

- [crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/) — SHA-256, SHA3-256, BLAKE3, and HMAC in one comparison.
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — Merkle trees and inclusion proofs built on SHA-256.
- [crypto-lab-collision-vault](https://systemslibrarian.github.io/crypto-lab-collision-vault/) — MD5/SHA-1 collisions and what breaks when collision resistance fails.
- [crypto-lab-mac-race](https://systemslibrarian.github.io/crypto-lab-mac-race/) — HMAC, CMAC, Poly1305, and GHASH message authentication.
- [crypto-lab-kdf-chain](https://systemslibrarian.github.io/crypto-lab-kdf-chain/) — HKDF, PBKDF2, scrypt, and Argon2id, the memory-hard KDFs hashes should not replace.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
