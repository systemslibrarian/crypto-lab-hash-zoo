# crypto-lab-hash-zoo

## What It Is

Hash Zoo is an interactive side-by-side comparison of three cryptographic hash functions: SHA-256 (Merkle-Damgård construction via `@noble/hashes/sha2`), SHA3-256 (Keccak sponge construction via `@noble/hashes/sha3`), and BLAKE3 (binary tree hash via `@noble/hashes/blake3`). It computes 256-bit digests, measures timing across 100 iterations, and visualizes the avalanche effect — how flipping a single input bit changes roughly half the output bits. The demo also shows SHA-256 Merkle-Damgård padding and SHA-3 rate/capacity parameters to illustrate the structural differences between constructions.

## When to Use It

- **Learning hash function internals.** The avalanche grid and construction diagrams make abstract concepts like sponge absorption and tree-parallel hashing concrete.
- **Comparing performance characteristics.** The timed hash table shows relative throughput of SHA-256, SHA3-256, and BLAKE3 on identical input in the browser.
- **Understanding construction trade-offs.** Side-by-side architecture diagrams clarify why SHA-3 resists length extension while bare Merkle-Damgård does not.
- **Teaching or presenting cryptography.** The live controls (message textarea, bit-position slider) make this suitable for classroom or conference demos.
- **Not for password hashing.** None of these hash functions are memory-hard; use Argon2id or similar KDFs for password storage.

## Live Demo

[https://systemslibrarian.github.io/crypto-lab-hash-zoo/](https://systemslibrarian.github.io/crypto-lab-hash-zoo/)

Type or paste any message into the textarea and click "Hash All Three" to see hex output, average timing, and construction metadata for all three algorithms. Use the bit-position slider in Section B to flip a single bit and watch the 16×16 avalanche grid animate which output bits changed. Click "Padding info" to inspect the SHA-256 padded block and SHA-3 rate/capacity split.

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

---

**Part of the [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) portfolio:**
[babel-hash](https://systemslibrarian.github.io/crypto-lab/babel-hash/) · [kdf-chain](https://systemslibrarian.github.io/crypto-lab/kdf-chain/) · [corrupted-oracle](https://systemslibrarian.github.io/crypto-lab/corrupted-oracle/) · [phantom-vault](https://systemslibrarian.github.io/crypto-lab/phantom-vault/)

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31
