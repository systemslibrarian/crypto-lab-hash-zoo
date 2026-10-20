# Hash Zoo — a hash from a block cipher

Brief: `brief-extension.md`. Slug: `crypto-lab-hash-zoo`.
Starting main: `c604e5c6bb209c3fcfb8af59d302a362df6cda63` (no drift).
Pages: https://systemslibrarian.github.io/crypto-lab-hash-zoo/

## Delivered

Section D precedes the existing Info Panel and contains four cards: real
AES-128 Davies–Meyer compression, a free-start inversion with feed-forward
removed, a computed fixed point, and a message-hash padding collision.
Every displayed block is an actual AES call using `@noble/ciphers`; the trace
prints its key, input, ciphertext and XOR output. Sections A–C retain their
original hash implementations, avalanche and SHA-256 length-extension paths.

The default hash uses a fixed zero IV and length-delimited padding. Zero-fill
is an explicitly broken option: a partial-block message and that message plus
a zero byte collide. Empty input is refused as a collision demonstration;
aligned inputs honestly report when the appended byte adds a block. A separate,
explicitly artificial chosen-IV experiment repeats the fixed-point block one,
two and three times under both padding rules.

The inverse shortcut has a real exception: when its recovered input is zero,
the feed-forward XOR changes nothing. The UI and tests show this as a neutral
zero-input exception instead of falsely claiming the shortcut always fails.
Fixed points themselves are neutral, not a green security verdict. All inputs
have exact byte-length validation, and edits retire results while no-op events
preserve them. The diagram and controls are readable at 320px.

## Sources and boundaries

NIST SP 800-38A F.1.1/F.1.2 supplies all four AES-128 ECB blocks, checked in
both directions and as the complete 64-byte example. No published
Davies–Meyer hash vector is claimed. FIPS 180-4 §6.2.2 confirms that SHA-256
adds working words modulo 2^32; the existing glossary was corrected so it
does not describe SHA-256 as the AES/XOR construction on this page.
The author-hosted Kelsey–Schneier expandable-message paper was checked for
the fixed-point context; an expandable-message attack is prose only.
The existing Info Panel already mentioned Davies–Meyer but had no executable
AES compression exhibit. No cross-repo runtime imports or shared catalog edits.

## Verification

- All 42 unit tests passed, including 11 new tests. Independent Node/OpenSSL
  AES checks 300 random compression/preimage/fixed-point cases, 200 hash chains,
  1,025 padding lengths, all NIST blocks, validation and the zero-input exception.
- §4.1a: structural gate changes only the section count and four-card structure;
  no new prose is pinned in the boot gate.
- §4.1b: all 48 browser claims passed, including six new claims using independent
  Node/OpenSSL AES to recompute the displayed blocks, both padding modes and
  all six chosen-IV chains. UTF-8, aligned and partial messages, malformed
  inputs, retirement and no-op behavior are exercised.
- §4.1c: all eight mutations were killed. `mutation-evidence.json` records a
  passing owning baseline, nonempty source diff, successful changed build,
  named zero-retry assertion failure, exact restoration and passing owning
  test. A served-JavaScript SHA-256 guard rejects stale-artifact evidence.
- §4.1d: correct AES block calls and correct compression coexist with the
  actual padding collision and the visible negative-claim sentence. Removing
  that sentence fails the owning test.
- All 51 browser tests passed, including desktop, 380px and 320px accessibility
  walks. After the final diagram/input polish, the 320px gate passed again.
  Grayscale and deuteranopia screenshots were inspected. No exemption was added.
- Local Chromium 153.0.8010.0 used an ignored config because the pinned browser
  download was unavailable. The original CI configuration remains unchanged.

## Catalog handoff — no shared edits

Suggested card sentence: “Build a teaching hash from real AES, invert the
missing feed-forward wire, and see correct compression collide under ambiguous
padding.” Add chips `Davies–Meyer` and `AES`; retain existing chips.
Implemented: `src/blockcipher/dm.ts` AES block calls, compression, inverse,
fixed point and two padding/hash chains; `src/blockcipher/panel.ts` four
interactive cards and chosen-IV comparison. Prose only: expandable messages
and general collision-resistance reductions.
Concept deepened: **3. Collision resistance and hash constructions**.

Final main SHA and exact served-byte proof are recorded after publication.
The shared deploy-sync checker remains blocked by missing unrelated fleet
clones; shared catalog, counsel, census and checker files remain unchanged.
