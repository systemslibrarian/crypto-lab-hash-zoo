# Extension brief — `crypto-lab-hash-zoo`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-hash-zoo` at `c604e5c6bb20` and `audits/_MASTER-TEMPLATE.md` (catalog
`f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the gap:
Katz–Lindell, *Introduction to Modern Cryptography*, 3rd ed., §6.2 (Construction 6.3,
Theorem 6.4) and §7.3.1 (Davies–Meyer, Theorem 7.5; compare Exercises 7.23–7.24).

**Verdict: extension — one new section, "Section D — A hash from a block cipher",
between Section C and the Info Panel.**

## What the lab has now

Read at `c604e5c6bb20`:

- Hashing is `@noble/hashes` only (`package.json` dependencies: `@noble/hashes`). SHA-256,
  SHA3-256 and BLAKE3 are imported at `src/hasher.ts:1–3`; `_SHA256` is used to resume
  from a published digest in `lengthExtend` (`src/hasher.ts:258`).
- Sections in `src/ui.ts`: `#hash-intro` (172), `#hash-comparison` A (191),
  `#avalanche-section` B (222), `#construction-section` C (269–348, the length-extension
  forgery), `#info-panel` (350–392), `#reduced-sha2` (393).
- **Davies–Meyer is a glossary term only.** `src/ui.ts:362`, inside the Merkle–Damgård
  tab's Advanced disclosure: *"The block compression uses a Davies-Meyer … construction
  over 64 rounds…"*. Nothing on the page builds or attacks a compression function.
- Tests: `src/hasher.test.ts` (Vitest; KATs for `""` and `"abc"`). `e2e/claims.spec.ts`
  uses `node:crypto` (OpenSSL) as an independent oracle (`createHash`, lines 1, 26–28).
  `e2e/gate.ts:122` asserts `#app main .panel` has count **5**; `:124` asserts four Info
  Panel tabs.
- At this commit the repo has **no `scripts/` directory, no mutation runner, and no §4.1d
  negative-claim test** (`grep -in negative e2e/claims.spec.ts` → nothing). The new
  section brings the first of each; do not retrofit the existing sections.

## What to add

One new `section.panel` with id `blockcipher-section`, four steps on **real AES-128**.
Notation follows Katz–Lindell: `h(k, x) = F_k(x) ⊕ x`, where the **message block `k` is
the cipher key** and the **chaining value `x` is the cipher input**.

1. **Davies–Meyer, shown.** One 16-byte message block (as AES key) and one 16-byte chaining
   value go in; the page draws the cipher box and the feed-forward XOR line, and prints
   `F_k(x)`, `x`, and `h(k, x)`. 256 bits in, 128 bits out: that is the compression.
2. **Remove the feed-forward (break-it-yourself).** Toggle "feed-forward" off, so
   `h'(k, x) = F_k(x)`. The learner types (or keeps the default) a target 128-bit value
   `y` and any message block `k`; the page computes `x = F_k⁻¹(y)` with one AES
   decryption and shows `h'(k, x) = y` — **a preimage in one decryption**. Turn the
   feed-forward back on and run the same trick: the page shows `F_k(x) ⊕ x ≠ y` and says
   why: decryption no longer inverts the function, because `x` now appears on both sides.
   Label this honestly as a **free-start** result: the attacker picks the chaining value
   too, which a fixed-IV hash does not allow at the first block.
3. **Fixed points.** For the current message block `m`, the page computes
   `x* = F_m⁻¹(0¹²⁸)` and shows `h(m, x*) = F_m(x*) ⊕ x* = 0 ⊕ x* = x*`. Real, instant, and
   by itself harmless against a fixed IV — reaching `x*` from the IV is a 2¹²⁸ search.
   The prose names where fixed points can matter: long-message second-preimage attacks
   built on expandable messages (Kelsey–Schneier, EUROCRYPT 2005 — see the scoping note
   under Sources). Prose only; not executed here.
4. **Merkle–Damgård, with and without the length block.** A small MD hash over the same
   Davies–Meyer step, 16-byte blocks, a labelled constant IV. Two padding modes:
   - **Zero-fill only** (append zeros to the next 16-byte boundary, no length). The learner
     enters any message whose length is not a multiple of 16; the page hashes `m` and
     `m ‖ 0x00` and they collide — every AES call real, every block computed correctly.
   - **Katz–Lindell Construction 6.3** (append a `1` bit, zeros, then the bit length `L` as
     a 64-bit field in the last block). The same pair no longer collides. A short
     disclosure walks Theorem 6.4's Case 1 (different lengths ⇒ different last blocks) in
     two sentences.
   - **Chosen-IV fixed-point demo (labelled as such).** With the IV set to `x*` for a
     one-block message `m`, zero-fill mode gives `H(m) = H(m‖m) = H(m‖m‖m)`; Construction
     6.3 gives three different digests. The label says a real hash fixes its IV, and this
     shows what the length block buys even so.

**The one headline mechanism:** the feed-forward XOR is the only thing between "a block
cipher" and "a one-way compression function" — remove it and a single decryption is a
preimage.

**Plain-language intro (2–4 sentences, no math, before any hex):** SHA-256 is built by
taking a block cipher and wiring its own input back into its output. This section builds a
small hash that way from AES, then removes one wire at a time to show what each one is for.

**One honest scale note on the page:** a 128-bit chaining value means a birthday collision
costs about 2⁶⁴ AES calls, so this is a teaching hash, not a usable one; SHA-256 uses a
256-bit chaining value, and its feed-forward is word-wise addition mod 2³² rather than XOR
(FIPS 180-4 §6.2.2, step 4). Correct the Advanced glossary sentence at `src/ui.ts:362` to
say "a Davies–Meyer-style construction: the 64-round block cipher's output is added,
word by word mod 2³², to the previous chaining value", and link it to Section D.

## Why it belongs here and not in a new lab

Hash Zoo already teaches Merkle–Damgård, padding and length extension on the same page;
its own glossary names Davies–Meyer and stops. Section D is the missing layer underneath
Section C — one concept (how the hash is built), not a second one.

## SECURITY / CORRECTNESS INVARIANTS

1. Every AES call is real AES-128 from a named library (below), checked against published
   vectors. No step is drawn from a precomputed table.
2. The feed-forward toggle defaults to **on**. The no-feed-forward variant is visibly marked
   as the broken variant whenever it is selected.
3. The zero-fill padding mode defaults to **off**; Construction 6.3 is the default MD mode.
4. Every "collision", "preimage" and "fixed point" verdict is computed by comparing bytes
   the page itself produced, and re-checked independently in `e2e/claims.spec.ts`.
5. The chosen-IV demo is the only place the IV is user-settable, and it says so in the
   verdict text ("chosen IV").
6. Existing Sections A–C, the Info Panel tabs, and every existing digest are unchanged.

## ARCHITECTURE

- Add `@noble/ciphers` (same major as the fleet uses, `^2.4.0` in e.g.
  `crypto-lab-hidden-bit/package.json:23`). Use `ecb(key, { disablePadding: true })` for
  single-block encrypt/decrypt, as `crypto-lab-hidden-bit/src/schemes/aes-modes.ts:1,30`
  does. Why not WebCrypto: it has no raw AES block decrypt, and step 2 needs `F_k⁻¹`.
- `src/blockcipher/dm.ts` — pure functions: `aesEncryptBlock`, `aesDecryptBlock`,
  `daviesMeyer(k, x)`, `noFeedForward(k, x)`, `preimageNoFF(k, y)`, `fixedPoint(m)`,
  `mdHash(message, { padding: 'zero-fill' | 'kl-6.3', iv })`, `padZeroFill`, `padKL63`.
- `src/blockcipher/dm.test.ts` — Vitest (unit level; see Tests).
- `src/ui.ts` — render the new section; keep its state separate from Sections A–C.
- `// [extension] point` markers: (a) in `mdHash` beside the padding switch (for a later
  Kelsey–Schneier expandable-message act); (b) in `dm.ts` beside the compression function
  (for the other PGV-secure modes such as Matyas–Meyer–Oseas and Miyaguchi–Preneel).

## UI

Four numbered steps in one section, top to bottom, each a card:
1. Inputs: message block `k` (hex or text → 16 bytes, shown), chaining value `x`.
   Output row: `F_k(x)`, `x`, `h(k,x)` with the XOR drawn.
2. Feed-forward switch + target `y` input + "Find a preimage" button. Result card shows
   `x = F_k⁻¹(y)` and the recomputed `h'(k, x)` beside `y`.
3. "Find a fixed point for this block" button → `x*`, then `h(m, x*)` beside `x*`.
4. Message textarea, padding-mode radio group (default Construction 6.3), "Hash m and
   m‖00" button, two digests side by side with a byte-diff; "Chosen-IV fixed point" button.

Stacks below 640px; inputs are real `<input>`/`<textarea>` with visible labels; result
regions `role="status" aria-live="polite"`.

## VISUAL SEMANTICS

- A preimage found against the no-feed-forward variant, and a collision under zero-fill,
  read as **ALARM** (broken construction), never green success: icon + text + colour.
- The same attempts against Davies–Meyer with feed-forward / Construction 6.3 read as
  **HELD** ("decryption does not invert it", "lengths differ, last blocks differ").
- The fixed point reads **NEUTRAL** with its text: "a fixed point exists; reaching it from a
  fixed IV is the hard part."
- Never colour alone; check grayscale and deuteranopia per §1.

## EDGE CASES

| Input | Behaviour |
|---|---|
| `k` or `x` not exactly 16 bytes after parsing | refuse, name the length received; no compute |
| non-hex characters in a hex field | refuse with the offending position |
| empty message in step 4 | refuse to claim a collision; explain that zero-fill needs a partial block |
| message length a multiple of 16 in zero-fill mode | `m` and `m‖00` still differ in block count; page says so and suggests a non-aligned length (teaches *why* the collision needs a partial block) |
| target `y` equal to `x` in step 2 | still valid; show it, no special case |
| editing any input after a verdict | retire the verdict and say it was retired (§4.1b retirement) |

## Tests

**KATs (Vitest, `src/blockcipher/dm.test.ts`).** AES-128 against NIST SP 800-38A
Appendix F.1.1 ECB-AES128.Encrypt — **all four blocks** (multi-block, per the batch rule):
key `2b7e151628aed2a6abf7158809cf4f3c`; plaintexts `6bc1bee22e409f96e93d7e117393172a`,
`ae2d8a571e03ac9c9eb76fac45af8e51`, `30c81c46a35ce411e5fbc1191a0a52ef`,
`f69f2445df4f9b17ad2b417be66c3710` → ciphertexts `3ad77bb40d7a3660a89ecaf32466ef97`,
`f5d3d58503b9699de785895a96fdbaaf`, `43b1cd7f598ece23881b00e3ed030688`,
`7b0c785e27e8ad3f8223207104725dd4`. Decrypt each back. There is no published vector for an
AES-128 Davies–Meyer hash; do not invent one — use the independent re-derivations below.

Unit properties: `aesDecryptBlock(k, aesEncryptBlock(k, x)) = x`; `daviesMeyer(m,
fixedPoint(m)) = fixedPoint(m)`; `noFeedForward(k, preimageNoFF(k, y)) = y`;
`daviesMeyer(k, preimageNoFF(k, y)) ≠ y` for a sampled set; `padKL63` ends with the 64-bit
big-endian bit length and is block-aligned; zero-fill pads `m` and `m‖00` identically when
`|m| mod 16 ≠ 0`.

**`e2e/claims.spec.ts` additions — independent oracle is `node:crypto`**
(`createCipheriv('aes-128-ecb', key, null)` with `setAutoPadding(false)`), not
`@noble/ciphers`:
- Step 1: recompute `AES_k(x) ⊕ x` in Node from the displayed `k`, `x`; assert equals the
  displayed `h(k,x)`.
- Step 2: from the displayed `k` and computed `x`, Node computes `AES_k(x)`; assert equals
  `y` (no feed-forward) and that `AES_k(x) ⊕ x ≠ y` (feed-forward), matching both verdicts.
- Step 3: Node computes `AES_m(x*)` and asserts it is all-zero.
- Step 4: Node re-implements both paddings and the MD chain and recomputes both digests for
  `m` and `m‖00`; assert the page's equality/inequality verdict matches Node's in each mode.
- Retirement: edit `m` after a verdict; assert the verdict is gone and the page says so.

**§4.1c mutations** — the new section renders verdicts, so record each as a concrete patch
(file, unique anchor, replacement) and run them from a script per §4.1c's
verdict-marker rule; model it on `crypto-lab-lfsr-forge/scripts/mutation-check.mjs` or
`crypto-lab-wep-crack/scripts/mutations.mjs` (both exist at their current HEADs). At
minimum:
1. Drop the XOR in `daviesMeyer` → the step 1 claims test fails.
2. Make `padKL63` omit the length field → the step 4 Construction 6.3 test fails.
3. Compute the fixed point with encrypt instead of decrypt → step 3 test fails.
4. Hard-wire the step 4 verdict to "collision" → the step 4 verdict test fails in 6.3 mode.

**§4.1d negative claim (this lab's first):**
> *"A compression function built from a sound block cipher does not make the hash
> collision-resistant if the padding is ambiguous."*

Evidence fixture: zero-fill mode, `m` = a 5-byte default message. Every AES call verifies
against the oracle, both digests are computed correctly, the verdict reads
**"EVERY BLOCK CORRECT — AND COLLIDING"**, and the negative-claim sentence is on screen in
that state. Assert all three per §4.1d; deleting the sentence must fail assertion 3.

**Structural gate:** update `e2e/gate.ts:122` from 5 to 6 panels. That is structure, so it
belongs there; put every copy assertion in `claims.spec.ts` (§4.1a).

## README and card follow-up

- README "What It Is": add one sentence naming the AES-based Davies–Meyer section and that
  it uses `@noble/ciphers`. "Exhibits": insert **Section D** after Section C (renumber the
  Info Panel item). "Tests": add the SP 800-38A vectors, the Node AES oracle, and the
  negative-claim test. "What Can Go Wrong": add "ambiguous padding" and "a block cipher
  without the feed-forward is invertible".
- Catalog handoff (do not edit `../crypto-lab`): the card could gain chips
  `Davies–Meyer` and `AES` (both implemented). The algorithm index will pick up AES from
  source on the next `catalog-evidence` run.

## Do not touch

The `@noble/hashes` imports and every existing digest, the length-extension code path and
its tests, the avalanche sections, the reduced-round research section, the header, theme
pin and footer.

## Sources

- Katz & Lindell, *Introduction to Modern Cryptography*, 3rd ed., CRC Press, 2021 (ISBN
  9780815354369): §6.2 Construction 6.3 and Theorem 6.4; §7.3.1 Davies–Meyer and
  Theorem 7.5; Exercises 7.23–7.24.
- B. Preneel, R. Govaerts, J. Vandewalle, "Hash Functions Based on Block Ciphers: A
  Synthetic Approach", CRYPTO '93, LNCS 773, pp. 368–378 (Springer, 1994). Verified at
  https://ftp.math.utah.edu/pub/tex/bib/idx/lncs1994/773/0/368-378.html
- J. Black, P. Rogaway, T. Shrimpton, "Black-Box Analysis of the Block-Cipher-Based
  Hash-Function Constructions from PGV", CRYPTO 2002, LNCS 2442, pp. 320–335,
  doi:10.1007/3-540-45708-9_21. Verified at https://iacr.org/cryptodb/data/paper.php?pubkey=889
- R. C. Merkle, "One Way Hash Functions and DES", CRYPTO '89, LNCS 435, pp. 428–446,
  doi:10.1007/0-387-34805-0_40; I. Damgård, "A Design Principle for Hash Functions",
  CRYPTO '89, LNCS 435, pp. 416–427. DOI checked at doi.org for Merkle; page ranges from
  the ECRYPT eHash wiki (https://ehash.isec.tugraz.at/wiki/HashIntro.html). The Damgård
  DOI was not reachable from here — cite without it, or confirm it before adding.
- NIST SP 800-38A (2001), Appendix F.1.1 ECB-AES128 — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
- NIST FIPS 180-4, §6.2.2 step 4 (word-wise addition mod 2³² of the working variables to
  the previous hash value) — https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
- Prose only, not executed: J. Kelsey, B. Schneier, "Second Preimages on n-bit Hash
  Functions for Much Less than 2ⁿ Work", EUROCRYPT 2005, Springer, pp. 474–490 (verified
  at https://www.schneier.com/academic/archives/2005/01/second_preimages_on.html; its
  abstract describes expandable messages and does not mention Davies–Meyer, so the page
  should say "fixed points are one cheap way to build the expandable messages this attack
  needs" only if the agent confirms that sentence in the paper body; otherwise cite it for
  expandable messages alone).
