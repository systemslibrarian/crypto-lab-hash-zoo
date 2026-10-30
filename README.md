# crypto-lab-hash-zoo

## What It Is

Hash Zoo is an interactive side-by-side comparison of four cryptographic hash functions: SHA-256 (Merkle-Damgård construction via `@noble/hashes/sha2`), SHA3-256 and original Keccak-256 (sponge constructions with different suffixes via `@noble/hashes/sha3`), and BLAKE3 (binary tree hash via `@noble/hashes/blake3`). It opens with a plain-language "what is a hash?" on-ramp, then computes 256-bit digests, visualizes the avalanche effect — how flipping a single input bit changes roughly half the output bits — showing the flipped input bit next to the output storm, and demonstrates the flagship structural difference between constructions by performing a **real, live SHA-256 length-extension forgery** in the browser. A same-message explanation distinguishes Keccak-256 from SHA3-256, including their suffix encodings and Ethereum compatibility, and links directly to Collision Vault for MD5/SHA-1 collisions. Timing across 100 iterations and SHA-256 padding / SHA-3 rate–capacity details are available as secondary, honestly-caveated views.

Section D adds an AES-128 Davies–Meyer teaching hash using `@noble/ciphers`, with free-start preimages, fixed points, and an ambiguous-padding collision. It preserves the existing full-round hash comparison and length-extension paths.

Every digest, forged tag, and avalanche count in Sections A–C is computed in-browser from the real `@noble/hashes` primitives — no hardcoded or faked output. The length-extension forgery is proven at runtime by recomputing SHA-256 over the reconstructed message from scratch and asserting equality.

## Exhibits

1. **Start here — What is a hash?** A one-input / one-output live example with the three defining rules (deterministic, fixed-size, one-way/unpredictable). Defines a hash before comparing hashes.
2. **Section A — Hash Comparison.** SHA-256, SHA3-256, Keccak-256, and BLAKE3 side-by-side: 256-bit digests, output size, internal state, and construction, with plain-language annotations. Indicative timing is tucked behind a "show timing" toggle (see the caveat below).
3. **Section B — Avalanche Effect.** Flip one input bit (shown highlighted in an input-bit strip) and watch ~50% of the 256 output bits flip. A per-byte heatmap encodes how many bits changed in each output byte (uniform diffusion), and a "flip every bit" sweep plots the distribution of output-diff percentages, showing ~50% is a statistical law, not one lucky result.
4. **Section C — Construction Comparison + length extension.** Merkle-Damgård, sponge, and tree diagrams, plus an interactive length-extension forgery: from a published SHA-256 tag and its length alone (never the secret bytes), append attacker data and produce a valid extended tag — then see it verified against a from-scratch recompute. Contrasts with the sponge's withheld capacity lane.
5. **Section D — A hash from a block cipher.** Wire a real AES block through feed-forward XOR, remove the wire to get a free-start preimage in one decryption, compute a fixed point, and compare zero-fill with length-delimited padding. Inspect every AES block of both message chains; a separate chosen-IV experiment repeats the fixed point. This 128-bit-state teaching hash is not for use.
6. **Info Panel.** Tabbed construction notes with inline jargon glossaries (IV, chaining value, rate/capacity, sponge, XOF, SIMD) and "Advanced" disclosures gating Davies-Meyer and Keccak-f[1600], plus guidance on choosing a hash function.

## When to Use It

- **Learning hash function internals.** The avalanche grid and construction diagrams make abstract concepts like sponge absorption and tree-parallel hashing concrete.
- **Comparing performance characteristics.** The timed hash table shows a rough, indicative feel for the relative cost of SHA-256, SHA3-256, Keccak-256, and BLAKE3 on identical input in the browser. It is *not* a benchmark — see the timing caveat below.
- **Understanding construction trade-offs.** Side-by-side architecture diagrams clarify why SHA-3 resists length extension while bare Merkle-Damgård does not.
- **Teaching or presenting cryptography.** The live controls (message textarea, bit-position slider) make this suitable for classroom or conference demos.
- **Not for password hashing.** None of these hash functions are memory-hard; use Argon2id or similar KDFs for password storage.
- Do NOT use this as a crypto library — it is a browser teaching demo for comparing hash constructions.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/)**

Start with the "what is a hash?" box and type to watch a live fingerprint. Type or paste any message into the Section A textarea and click "Hash All Four" to see hex output and construction metadata for all four algorithms (timing lives behind the "show indicative timing" toggle). Use the bit-position slider in Section B to flip a single bit — the flipped input bit is highlighted in an input strip beside the 16×16 avalanche grid — then run the "flip every bit" sweep to see the ~50% distribution. In Section C, run the length-extension forgery to watch a valid extended SHA-256 tag appear from a published tag alone. Click "Padding info" to inspect the SHA-256 padded block and SHA-3 rate/capacity split.

## About the Timings (read before comparing speeds)

The "Time (avg µs)" row is an in-browser average over 100 iterations. It is deliberately labelled *indicative only*, both here and in the app, because single-digit-microsecond measurements taken with `performance.now()` in a JS engine are dominated by noise: JIT warmup, garbage-collection pauses, CPU frequency scaling, and background tab activity all move the numbers around. Do not read the ordering as a definitive speed ranking — on tiny inputs the measurements can approach clock granularity and be dominated by noise. BLAKE3's real speed advantage shows up on large inputs with SIMD and multithreading, which a single-threaded browser loop cannot exercise. For a real comparison, benchmark native builds (for example `b3sum` vs `openssl dgst`) on megabyte-scale inputs. The digests themselves are exact and verified against known-answer test vectors (see below).

## Keccak-256 versus SHA3-256

Both use Keccak-f[1600] with 24 rounds, a 1088-bit rate, a 512-bit capacity, and a 256-bit digest. SHA3-256 adds the SHA-3 domain-separation suffix before padding. For byte-aligned input, the combined suffix/padding encodings are `0x06` for SHA3-256 and `0x01` for original Keccak-256. They give different digests and must not be substituted for each other. The encodings are handled by the primitives; users should not append these bytes to the message themselves.

Enter `abc`, then clear the input, to compare both functions in Section A. Keccak-256 also participates in the avalanche cards, every-bit sweep, indicative timing, and copy controls. MD5 and SHA-1 remain in [Collision Vault](https://systemslibrarian.github.io/crypto-lab-collision-vault/), where published pairs demonstrate their broken collision resistance.

Sources: [Keccak Team specification summary](https://keccak.team/keccak_specs_summary.html) and [Ethereum's Merkle Patricia trie documentation](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/).

## What Can Go Wrong

- **A block cipher without feed-forward is invertible.** A free-start adversary can choose a chaining input by one AES decryption. With XOR, that shortcut is not a general inversion method; the all-zero input is an explicitly shown exception.
- **Ambiguous padding.** Correct AES calls and correct compression steps cannot rescue zero-fill padding: a non-aligned message and the same message followed by a zero byte have identical padded bytes. The length-delimited default separates this pair.

- **Length extension on bare SHA-256.** Merkle-Damgård hashes expose their internal state as the final digest, allowing an attacker to append data and compute a valid hash without knowing the original message. For message authentication, use a specified keyed construction such as HMAC-SHA256, KMAC, or BLAKE3 keyed mode, and verify the tag before acting on the message. Switching to a plain unkeyed SHA-3 or BLAKE3 digest does not authenticate a sender; resistance to this length-extension attack alone does not establish MAC security.
- **Confusing hash speed with password safety.** SHA-256, SHA3-256, Keccak-256, and BLAKE3 are all fast hashes — unsuitable for password storage because an attacker can brute-force billions of guesses per second.
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
npm run test:e2e    # Playwright: rendered-claim gate + axe-core accessibility gate
```

`src/hasher.test.ts` asserts:

- **Known-answer vectors.** SHA-256, SHA3-256, and BLAKE3 digests of `""` and `"abc"` are checked against the published standard vectors (FIPS 180-4, FIPS 202, BLAKE3 reference). Swapping a source import (for example `sha3` → `sha256`) fails these tests immediately.
- **Keccak-256 independent vectors.** Ten fixed values in `src/fixtures/keccak-vectors.json`, computed with PyCryptodome 4.2.0 (`Crypto.Hash.keccak.new(digest_bits=256, data=message.encode("utf-8")).hexdigest()`), cover empty input, `abc`, the default message, Unicode, and 135/136/137/271/272/273-byte inputs around the 136-byte sponge rate. Both unit and browser tests check these values; a swapped SHA3-256 implementation fails them. Browser checks also verify the Keccak-labelled copy button and an independently computed avalanche count. PyCryptodome is an offline fixture source, not a runtime dependency.
- **Distinctness.** The four algorithms produce different digests for the same input.
- **Avalanche ~50%.** Averaged over many single-bit input flips, each algorithm changes close to half of the 256 output bits (asserted within 42–58%). The every-bit distribution sweep is asserted the same way, with bucket counts summing to the number of flips.
- **Length-extension forgery is real.** `lengthExtend` resumes SHA-256 from a published digest, appends attacker data, and the test asserts the forged tag equals `SHA-256(secret ‖ glue ‖ append)` recomputed from scratch — for several secrets and an empty append — so the demo cannot ship a faked forgery. `sha256GluePadding` is checked for the `0x80` marker, block alignment, and big-endian length tail.
- **Pure-function correctness.** `popcount` over all 256 byte values, `flipBit` (exactly one bit changed, input not mutated, MSB-first, range/empty guards), `diffBitmap` (bit locations and counts), and `paddingInfo` (SHA-256 Merkle–Damgård `0x80` marker, 512-bit block alignment, big-endian length tail; SHA-3 rate+capacity = 1600).

The unit suite proves the *functions* are right; `e2e/claims.spec.ts` (Playwright, real Chromium
against the built bundle) proves the *page* is right, so a correct hasher rendered into a wrong
verdict cannot ship either. It asserts:

- **The digests on screen are the real digests.** SHA-256 and SHA3-256 are checked against Node's
  OpenSSL bindings — an oracle independent of `@noble` — and BLAKE3 against the published reference
  vectors, plus determinism, fixed 256-bit output for a 1-character and a 20,000-character message,
  and that one edited character moves all four.
- **Every counter is internally consistent.** For each avalanche card the `N/256 bits (P%)` headline
  must equal the number of `changed` cells actually drawn, the 32 per-byte heatmap values must sum
  back to `N`, the meter width must be `P`, and the exact `N` is cross-checked against a
  bit-difference computed in the test. The every-bit sweep's 20 histogram buckets must sum to the
  number of flips it claims to have run.
- **The forgery is a real forgery.** The forged tag must equal SHA-256 of `secret ‖ glue ‖ append`
  recomputed in the test — for the default secret, an empty append, and secret lengths that straddle
  the 56/64-byte padding boundary — and the glue padding is checked for its `0x80` marker, block
  alignment and big-endian length tail.
- **Every failure path reaches its failure state and says why.** Empty message (controls disabled,
  avalanche and sweep refuse with an explanation), empty secret (forgery refuses), a rejected
  clipboard write, and attacker-supplied HTML in the append field being escaped rather than executed.
  Each also asserts the live-region announcement matches what is on screen.

`npm test` runs only the Vitest unit suite; the Playwright suite in `e2e/` is excluded from it and
run separately via `npm run test:e2e` (`npm run test:a11y` is the same command, kept as an alias).

Section D adds 11 unit tests (52 total including Keccak fixtures), including all four AES-128 ECB blocks
from NIST SP 800-38A F.1.1/F.1.2 in both directions and the complete 64-byte
example. There is no claimed published AES-based Davies–Meyer hash vector.
Randomized properties and both MD padding chains are checked against Node’s
independent OpenSSL AES; tests cover 1,025 padding lengths and the zero-input
feed-forward exception. `@types/node` is a development-only dependency for
those independent test oracles.

Six new browser claims independently recompute every displayed AES block,
compression, preimage, fixed point, hash pair and chosen-IV chain with OpenSSL.
The negative fixture has correct AES calls and equal digests alongside the
visible warning that a sound block cipher cannot fix ambiguous padding.
`npm run test:mutations:dm` exercises concrete source faults, changed bundle
hashes, named zero-retry failures and exact restored artifacts. The runner
refuses to count stale served scripts as mutation kills.

The new section is included in the complete accessibility walks, with an
additional 320px state walk. No header, theme, footer, existing hash primitive,
length-extension code or reduced-round research exhibit is changed.

Sources: [NIST SP 800-38A, Appendix F](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf);
[FIPS 180-4 §6.2.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf);
Katz–Lindell, third edition, §6.2 Construction 6.3 and §7.3.1;
[Kelsey–Schneier, EUROCRYPT 2005](https://www.schneier.com/academic/archives/2005/01/second_preimages_on.html)
for expandable messages only (the long-message attack is not executed here).
The glossary now distinguishes SHA-256’s word-wise addition from this XOR.

## Related Demos

- [crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/) — SHA-256, SHA3-256, BLAKE3, and HMAC in one comparison.
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — Merkle trees and inclusion proofs built on SHA-256.
- [crypto-lab-collision-vault](https://systemslibrarian.github.io/crypto-lab-collision-vault/) — MD5/SHA-1 collisions and what breaks when collision resistance fails.
- [crypto-lab-mac-race](https://systemslibrarian.github.io/crypto-lab-mac-race/) — HMAC, CMAC, Poly1305, and GHASH message authentication.
- [crypto-lab-kdf-chain](https://systemslibrarian.github.io/crypto-lab-kdf-chain/) — HKDF, PBKDF2, scrypt, and Argon2id, the memory-hard KDFs hashes should not replace.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Reduced-round research context

The live demo links [2026/232](https://eprint.iacr.org/2026/232) and [2026/1120](https://eprint.iacr.org/2026/1120), distinguishes reported reduced-round results from standard full-round SHA-2, and identifies the September result as a preprint. This lab does not verify the pair itself; the linked Collision Vault exhibit now provides that execution under explicit conventions.

The supplied 36-step SHA-256 Table 2 pair is now verified in [Collision Vault](https://systemslibrarian.github.io/crypto-lab-collision-vault/#sha2-pair-verifier), with exact IV/step/padding conventions, mutation controls and full SHA-256 contrast. This lab still computes its own full-round hashes and does not execute the paper attack.
