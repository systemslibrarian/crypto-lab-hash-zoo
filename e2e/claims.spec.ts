import { createHash } from 'node:crypto';
import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate for the claims this lab makes on screen.
 *
 * The a11y spec next door proves the page is reachable; this one proves it is
 * *right*: that the digests it prints are the real digests, that the avalanche
 * counters agree with the cells they are counting, that the every-bit sweep's
 * buckets sum to the flips it says it ran, that the length-extension forgery
 * really is a valid SHA-256 of the reconstructed message, and that every
 * failure path the UI offers actually reaches its failure state and says why.
 *
 * Independent oracles, so a wrong page cannot mark its own homework:
 *   - SHA-256 and SHA3-256 come from node's crypto (OpenSSL), not @noble.
 *   - BLAKE3 has no node binding, so it is checked against the published
 *     reference vectors for "" and "abc" and otherwise held to structural and
 *     internal-consistency checks.
 */

const DEFAULT_MESSAGE = 'The quick brown fox jumps over the lazy dog';

// Published BLAKE3 reference vectors (same values the unit suite asserts).
const BLAKE3_EMPTY = 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262';
const BLAKE3_ABC = '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85';

function nodeHash(algo: 'sha256' | 'sha3-256', message: string | Uint8Array): string {
  return createHash(algo).update(Buffer.from(message as never)).digest('hex');
}

function utf8(message: string): Uint8Array {
  return new Uint8Array(Buffer.from(message, 'utf8'));
}

/** Count differing bits between two hex digests — the avalanche oracle. */
function hexDiffBits(a: string, b: string): number {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  let bits = 0;
  for (let i = 0; i < ba.length; i += 1) {
    let x = ba[i] ^ bb[i];
    while (x !== 0) {
      x &= x - 1;
      bits += 1;
    }
  }
  return bits;
}

function flipBit(bytes: Uint8Array, bitPosition: number): Uint8Array {
  const out = bytes.slice();
  out[Math.floor(bitPosition / 8)] ^= 1 << (7 - (bitPosition % 8));
  return out;
}

/** The SHA-256 glue padding for a message of msgLen bytes, computed here. */
function gluePadding(msgLen: number): Buffer {
  const out: number[] = [0x80];
  while ((msgLen + out.length) % 64 !== 56) out.push(0x00);
  const tail = Buffer.alloc(8);
  tail.writeBigUInt64BE(BigInt(msgLen) * 8n);
  return Buffer.concat([Buffer.from(out), tail]);
}

async function setMessage(page: Page, value: string): Promise<void> {
  await page.locator('#message-input').fill(value);
}

/** The three hex digests currently rendered in the Section A output row. */
async function renderedDigests(page: Page): Promise<string[]> {
  const cells = page.locator('#hash-results tr').first().locator('td .hex-wrap');
  await expect(cells).toHaveCount(3);
  return (await cells.allTextContents()).map((t) => t.trim());
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#hash-results .hex-wrap').first()).not.toBeEmpty();
});

// ---------------------------------------------------------------------------
// Section A — the three digests are the real digests.
// ---------------------------------------------------------------------------

test.describe('Section A: hash comparison', () => {
  test('prints the real SHA-256 / SHA3-256 / BLAKE3 digests of the message', async ({ page }) => {
    await page.locator('#hash-btn').click();
    const [sha256, sha3, blake3] = await renderedDigests(page);

    expect(sha256).toBe(nodeHash('sha256', DEFAULT_MESSAGE));
    expect(sha3).toBe(nodeHash('sha3-256', DEFAULT_MESSAGE));

    // All three are 256-bit, as the "Output size" row claims.
    for (const hex of [sha256, sha3, blake3]) {
      expect(hex).toMatch(/^[0-9a-f]{64}$/);
    }
    await expect(page.locator('#hash-results tr').nth(1).locator('td')).toHaveText([
      '256 bits',
      '256 bits',
      '256 bits',
    ]);

    // Distinct constructions, distinct digests.
    expect(new Set([sha256, sha3, blake3]).size).toBe(3);
  });

  test('matches published vectors for the empty message and "abc", including BLAKE3', async ({
    page,
  }) => {
    await setMessage(page, '');
    let [sha256, sha3, blake3] = await renderedDigests(page);
    expect(sha256).toBe(nodeHash('sha256', ''));
    expect(sha3).toBe(nodeHash('sha3-256', ''));
    expect(blake3).toBe(BLAKE3_EMPTY);

    await setMessage(page, 'abc');
    [sha256, sha3, blake3] = await renderedDigests(page);
    expect(sha256).toBe(nodeHash('sha256', 'abc'));
    expect(sha3).toBe(nodeHash('sha3-256', 'abc'));
    expect(blake3).toBe(BLAKE3_ABC);
  });

  test('is deterministic and fixed-size: same input same output, any size in, 256 bits out', async ({
    page,
  }) => {
    await page.locator('#hash-btn').click();
    const first = await renderedDigests(page);
    await page.locator('#hash-btn').click();
    expect(await renderedDigests(page)).toEqual(first);
    await expect(page.locator('.consistency')).toHaveText('Same input -> same output.');

    // A one-character message and a 20,000-character one both come out 64 hex.
    for (const message of ['a', 'z'.repeat(20_000)]) {
      await setMessage(page, message);
      const digests = await renderedDigests(page);
      for (const hex of digests) expect(hex).toMatch(/^[0-9a-f]{64}$/);
      expect(digests[0]).toBe(nodeHash('sha256', message));
      expect(digests[1]).toBe(nodeHash('sha3-256', message));
    }
  });

  test('one edited character changes all three digests', async ({ page }) => {
    await setMessage(page, 'hash zoo');
    const before = await renderedDigests(page);
    await setMessage(page, 'hash zoO');
    const after = await renderedDigests(page);
    for (let i = 0; i < 3; i += 1) expect(after[i]).not.toBe(before[i]);
    expect(after[0]).toBe(nodeHash('sha256', 'hash zoO'));
  });

  test('timing is hidden behind the toggle and reports real per-iteration numbers', async ({
    page,
  }) => {
    // A kilobyte-scale message so 100 iterations are comfortably above the
    // browser's clock granularity — the numbers must be real, not floor-zero.
    await setMessage(page, 'z'.repeat(5000));
    const host = page.locator('#timing-grid-host');
    await expect(host).toBeHidden();
    await page.locator('.timing-details summary').click();
    await expect(host).toBeVisible();

    const cells = host.locator('.timing-cell');
    await expect(cells).toHaveCount(3);
    await expect(host.locator('.timing-algo')).toHaveText(['SHA-256', 'SHA3-256', 'BLAKE3']);
    for (const text of await host.locator('.timing-num').allTextContents()) {
      const micros = Number(text.replace(' µs', ''));
      expect(Number.isFinite(micros)).toBe(true);
      expect(micros).toBeGreaterThan(0);
      // 100 iterations of a hash over a short string: sanity ceiling, not a
      // benchmark assertion (the README is explicit that these are indicative).
      expect(micros).toBeLessThan(10_000);
    }
    await expect(page.locator('.timing-note')).toContainText('Indicative only');
  });

  test('the copy button copies exactly the digest rendered beside it', async ({
    page,
    context,
  }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const [sha256] = await renderedDigests(page);
    const button = page.locator('#hash-results .copy-btn').first();
    expect(await button.getAttribute('data-copy')).toBe(sha256);

    await button.click();
    await expect(button).toHaveText('Copied');
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(sha256);
    await expect(page.locator('#aria-live-region')).toHaveText('Hash copied to clipboard');
    await expect(button).toHaveText('Copy', { timeout: 5000 });
  });

  test('FAILURE PATH: a rejected clipboard write reports the failure', async ({ page }) => {
    await page.evaluate(() => {
      Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: { writeText: () => Promise.reject(new Error('denied')) },
      });
    });
    const button = page.locator('#hash-results .copy-btn').first();
    await button.click();
    await expect(button).toHaveText('Failed');
    await expect(page.locator('#aria-live-region')).toHaveText('Copy failed');
  });
});

// ---------------------------------------------------------------------------
// Intro — the "what is a hash?" one-liner.
// ---------------------------------------------------------------------------

test.describe('Intro: what is a hash', () => {
  test('the live fingerprint is a real, abbreviated SHA-256 of the typed text', async ({ page }) => {
    const code = page.locator('#intro-hash');
    for (const value of ['hello', 'hellp']) {
      await page.locator('#intro-input').fill(value);
      const full = nodeHash('sha256', value);
      await expect(code).toHaveAttribute('title', full);
      // The short form is the head and tail of the very digest in the title.
      await expect(code).toHaveText(`${full.slice(0, 12)}…${full.slice(-8)}`);
    }
  });
});

// ---------------------------------------------------------------------------
// Section B — avalanche counters that agree with themselves.
// ---------------------------------------------------------------------------

/** Parse "Changed: 130/256 bits (50.8%)". */
async function readCard(card: Locator): Promise<{
  algo: string;
  diffBits: number;
  total: number;
  percent: number;
}> {
  const meta = ((await card.locator('.algo-meta').textContent()) ?? '').trim();
  const match = meta.match(/Changed:\s*(\d+)\/(\d+)\s*bits\s*\(([\d.]+)%\)/);
  expect(match, `unparseable card meta: ${meta}`).not.toBeNull();
  return {
    algo: ((await card.locator('h3').textContent()) ?? '').trim(),
    diffBits: Number(match![1]),
    total: Number(match![2]),
    percent: Number(match![3]),
  };
}

test.describe('Section B: avalanche effect', () => {
  test('every counter agrees with the grid, the heatmap and the meter it summarises', async ({
    page,
  }) => {
    await page.locator('#analyze-btn').click();
    const cards = page.locator('#avalanche-grids .algo-card');
    await expect(cards).toHaveCount(3);

    for (let i = 0; i < 3; i += 1) {
      const card = cards.nth(i);
      const { algo, diffBits, total, percent } = await readCard(card);

      // The whole: 256 bits, exactly as many cells as bits.
      expect(total).toBe(256);
      await expect(card.locator('.bit-cell')).toHaveCount(256);
      // The parts: changed + unchanged cells partition the grid...
      await expect(card.locator('.bit-cell.changed')).toHaveCount(diffBits);
      await expect(card.locator('.bit-cell.same')).toHaveCount(256 - diffBits);
      // ...and the percentage is that count, not a separate opinion.
      expect(percent).toBeCloseTo((diffBits / 256) * 100, 1);

      // Per-byte heatmap: 32 bytes whose per-byte counts sum back to diffBits.
      const heat = await card.locator('.heat-cell').evaluateAll((els) =>
        els.map((el) => Number(/heat-(\d+)/.exec(el.className)?.[1] ?? -1)),
      );
      expect(heat).toHaveLength(32);
      expect(heat.every((n) => n >= 0 && n <= 8)).toBe(true);
      expect(heat.reduce((a, b) => a + b, 0)).toBe(diffBits);

      // The heatmap's own aria summary quotes its real min and max.
      await expect(card.locator('.byte-heatmap')).toHaveAttribute(
        'aria-label',
        new RegExp(
          `changed between ${Math.min(...heat)} and ${Math.max(...heat)} of its 8 bits`,
        ),
      );

      // Meter fill is the percentage; the quality class is its distance from 50.
      const style = (await card.locator('.meter-fill').getAttribute('style')) ?? '';
      expect(style).toBe(`width:${percent.toFixed(1)}%`);
      const delta = Math.abs(percent - 50);
      const expected = delta <= 6 ? 'is-ideal' : delta <= 12 ? 'is-good' : 'is-off';
      await expect(card.locator('.meter')).toHaveClass(new RegExp(`\\b${expected}\\b`));

      // And the grid's screen-reader label repeats the same numbers.
      await expect(card.locator('.bit-grid')).toHaveAttribute(
        'aria-label',
        new RegExp(`^${algo.toLowerCase()}: ${diffBits} of 256 output bits changed, ${percent.toFixed(1)} percent`),
      );
    }
  });

  test('the bit counts equal an independently computed avalanche', async ({ page }) => {
    // Fixed message and fixed flip: the expected diff is exact, not statistical.
    const message = 'avalanche oracle';
    await setMessage(page, message);
    await page.locator('#bit-slider').fill('11');
    await page.locator('#analyze-btn').click();

    const original = utf8(message);
    const flipped = flipBit(original, 11);
    const expected = {
      SHA256: hexDiffBits(nodeHash('sha256', original), nodeHash('sha256', flipped)),
      'SHA3-256': hexDiffBits(nodeHash('sha3-256', original), nodeHash('sha3-256', flipped)),
    };

    const cards = page.locator('#avalanche-grids .algo-card');
    for (let i = 0; i < 3; i += 1) {
      const { algo, diffBits, percent } = await readCard(cards.nth(i));
      if (algo in expected) {
        expect(diffBits, `${algo} diff bits`).toBe(expected[algo as keyof typeof expected]);
      }
      // The headline "about half" claim, for all three including BLAKE3.
      expect(percent).toBeGreaterThan(25);
      expect(percent).toBeLessThan(75);
    }
  });

  test('the announced result quotes the percentages actually rendered', async ({ page }) => {
    await page.locator('#analyze-btn').click();
    const cards = page.locator('#avalanche-grids .algo-card');
    const shown = [];
    for (let i = 0; i < 3; i += 1) shown.push((await readCard(cards.nth(i))).percent.toFixed(1));
    await expect(page.locator('#aria-live-region')).toHaveText(
      `Flipped bit 0. Output bits changed: SHA-256 ${shown[0]} percent, SHA3-256 ${shown[1]} percent, BLAKE3 ${shown[2]} percent.`,
    );
  });

  test('the input strip shows the message bits and highlights exactly the flipped one', async ({
    page,
  }) => {
    const message = 'Hi!';
    await setMessage(page, message);
    await page.locator('#bit-slider').fill('9');

    const bytes = utf8(message);
    const expectedBits = [...bytes]
      .flatMap((b) => [...Array(8).keys()].map((i) => (b >> (7 - i)) & 1))
      .join('');

    const strip = page.locator('#input-strip');
    await expect(strip.locator('.ibit')).toHaveCount(bytes.length * 8);
    expect(((await strip.textContent()) ?? '').trim()).toBe(expectedBits);
    await expect(strip).toHaveAttribute(
      'aria-label',
      `Input bit strip: ${bytes.length * 8} bits, bit 9 flipped (highlighted).`,
    );

    const flipped = await strip
      .locator('.ibit')
      .evaluateAll((els) => els.flatMap((el, i) => (el.classList.contains('ibit-flip') ? [i] : [])));
    expect(flipped).toEqual([9]);

    // The prose label describes the same flip in byte/bit terms.
    const byte = bytes[1];
    await expect(page.locator('#bit-label')).toHaveText(
      `Flipping bit 9 (byte 1, bit 1) changes byte 0x${byte.toString(16).padStart(2, '0')} -> ` +
        `0x${(byte ^ 0b0100_0000).toString(16).padStart(2, '0')}.`,
    );
    await expect(page.locator('#bit-value')).toHaveText(`bit 9 / ${bytes.length * 8 - 1}`);
  });

  test('moving the slider recomputes against the newly flipped bit', async ({ page }) => {
    await page.locator('#analyze-btn').click();
    const cards = page.locator('#avalanche-grids .algo-card');
    const before = await readCard(cards.first());

    await page.locator('#bit-slider').fill('123');
    await expect(page.locator('#bit-value')).toHaveText('bit 123 / 343');
    const after = await readCard(cards.first());

    // A different input bit is a different experiment: the counter moved and
    // still agrees with its own grid.
    expect(after.diffBits).not.toBe(before.diffBits);
    await expect(cards.first().locator('.bit-cell.changed')).toHaveCount(after.diffBits);
    expect(after.diffBits).toBe(
      hexDiffBits(
        nodeHash('sha256', utf8(DEFAULT_MESSAGE)),
        nodeHash('sha256', flipBit(utf8(DEFAULT_MESSAGE), 123)),
      ),
    );
  });

  test('counts UTF-8 bytes, not characters', async ({ page }) => {
    await setMessage(page, 'né');
    // 'n' is 1 byte, 'é' is 2 -> 3 bytes -> 24 bits.
    await expect(page.locator('#bit-value')).toHaveText('bit 0 / 23');
    await expect(page.locator('#input-strip')).toHaveAttribute(
      'aria-label',
      /^Input bit strip: 24 bits/,
    );
    await expect(page.locator('#input-strip .ibit')).toHaveCount(24);
  });

  test('a long message truncates the strip and says so', async ({ page }) => {
    await setMessage(page, 'x'.repeat(100));
    const strip = page.locator('#input-strip');
    await expect(strip.locator('.ibit')).toHaveCount(512);
    await expect(strip.locator('.ibit-more')).toHaveCount(1);
    await expect(strip).toHaveAttribute(
      'aria-label',
      'Input bit strip: 800 bits, bit 0 flipped (highlighted). Showing the first bits only.',
    );
  });

  test('FAILURE PATH: an empty message disables the flip controls and says why', async ({
    page,
  }) => {
    await setMessage(page, '');
    await expect(page.locator('#bit-slider')).toBeDisabled();
    await expect(page.locator('#bit-value')).toHaveText('no message');
    await expect(page.locator('#message-preview')).toHaveText('Message: (empty)');
    await expect(page.locator('#bit-label')).toHaveText(
      'Message is empty, add at least one character to run avalanche analysis.',
    );
    await expect(page.locator('#input-strip')).toHaveText(
      'Add a message above to see its input bits.',
    );

    await page.locator('#analyze-btn').click();
    await expect(page.locator('#avalanche-grids')).toHaveText(
      'Add a message above to analyze the avalanche effect.',
    );
    await expect(page.locator('#avalanche-grids .algo-card')).toHaveCount(0);
  });
});

// ---------------------------------------------------------------------------
// Section B — the every-bit sweep.
// ---------------------------------------------------------------------------

test.describe('Section B: every-bit sweep', () => {
  for (const algo of ['sha256', 'sha3', 'blake3'] as const) {
    test(`the ${algo} sweep's buckets sum to the flips it reports`, async ({ page }) => {
      test.setTimeout(90_000);
      const message = 'sweep me across every single bit';
      await setMessage(page, message);
      await page.locator('#dist-algo').selectOption(algo);
      await page.locator('#dist-btn').click();

      const summary = page.locator('#dist-result .dist-summary');
      await expect(summary).toBeVisible({ timeout: 60_000 });
      const text = (await summary.textContent()) ?? '';
      const m = text.match(
        /^(\d+) single-bit flips · mean ([\d.]+)% · range ([\d.]+)–([\d.]+)%/,
      );
      expect(m, `unparseable sweep summary: ${text}`).not.toBeNull();
      const [flips, mean, min, max] = m!.slice(1).map(Number);

      // The whole: one flip per input bit.
      expect(flips).toBe(utf8(message).length * 8);

      // The parts: 20 histogram buckets whose counts sum back to the flips.
      const bars = page.locator('#dist-result .hist-bar');
      await expect(bars).toHaveCount(20);
      const counts = await bars.evaluateAll((els) =>
        els.map((el) => Number(/: (\d+) flips$/.exec((el as HTMLElement).title)?.[1] ?? -1)),
      );
      expect(counts.every((c) => c >= 0)).toBe(true);
      expect(counts.reduce((a, b) => a + b, 0)).toBe(flips);

      // Mean inside its own reported range, and the range inside [0,100].
      expect(mean).toBeGreaterThanOrEqual(min);
      expect(mean).toBeLessThanOrEqual(max);
      expect(min).toBeGreaterThanOrEqual(0);
      expect(max).toBeLessThanOrEqual(100);

      // The claim the section is making: the cluster sits on 50%.
      expect(mean).toBeGreaterThan(45);
      expect(mean).toBeLessThan(55);
      // Every non-empty bucket is inside the ranged window the summary quotes.
      const bucketSize = 5;
      counts.forEach((count, i) => {
        if (count === 0) return;
        expect(i * bucketSize).toBeLessThanOrEqual(max);
        expect((i + 1) * bucketSize).toBeGreaterThanOrEqual(min);
      });

      // The 50% column is the highlighted one, exactly once.
      const highlighted = await bars.evaluateAll((els) =>
        els.flatMap((el, i) => (el.classList.contains('hist-mid') ? [i] : [])),
      );
      expect(highlighted).toEqual([10]);

      // The chart's aria-label repeats the summary's numbers.
      await expect(page.locator('#dist-result .hist')).toHaveAttribute(
        'aria-label',
        new RegExp(
          `^${algo}: distribution of output-diff percent over ${flips} single-bit input flips\\. ` +
            `Mean ${mean.toFixed(1)} percent, range ${min.toFixed(1)} to ${max.toFixed(1)} percent`,
        ),
      );

      // And so does the announcement.
      await expect(page.locator('#aria-live-region')).toHaveText(
        `Swept ${flips} single-bit flips for ${algo}. Mean ${mean.toFixed(1)} percent output diff, clustered near 50 percent.`,
      );
    });
  }

  test('FAILURE PATH: sweeping an empty message refuses and says why (screen readers too)', async ({
    page,
  }) => {
    await setMessage(page, '');
    await page.locator('#dist-btn').click();
    await expect(page.locator('#dist-result')).toHaveText('Add a message above to run the sweep.');
    await expect(page.locator('#dist-result .hist-bar')).toHaveCount(0);
    // REGRESSION: this used to announce "Swept 0 single-bit flips ... Mean 0.0
    // percent output diff, clustered near 50 percent" — a statistic for a sweep
    // the page had just refused to run.
    await expect(page.locator('#aria-live-region')).toHaveText(
      'Add a message above to run the sweep.',
    );
  });
});

// ---------------------------------------------------------------------------
// Section C — the flagship length-extension forgery.
// ---------------------------------------------------------------------------

/** Read the five facts the forgery panel publishes. */
async function readForgery(page: Page): Promise<{
  publishedTag: string;
  reportedLen: number;
  glueHex: string;
  appended: string;
  forged: string;
  verify: string;
}> {
  const dds = await page.locator('#lext-result dd').allTextContents();
  expect(dds).toHaveLength(5);
  return {
    publishedTag: (await page.locator('#lext-result dd code').first().textContent()) ?? '',
    reportedLen: Number(/plus the length: (\d+) bytes/.exec(dds[0])?.[1] ?? NaN),
    glueHex: dds[1].trim(),
    appended: dds[2],
    forged: dds[3].trim(),
    verify: dds[4].trim(),
  };
}

test.describe('Section C: length-extension forgery', () => {
  test('the forged tag is a genuine SHA-256 of secret ‖ glue ‖ append', async ({ page }) => {
    // Rendered on load, no click required.
    const secret = 'secret-key||user=alice&role=guest';
    const append = '&role=admin';
    const f = await readForgery(page);

    // 1. The published tag really is SHA-256(secret), and the length is real.
    expect(f.publishedTag).toBe(nodeHash('sha256', secret));
    expect(f.reportedLen).toBe(utf8(secret).length);

    // 2. The glue padding is the padding SHA-256 would have appended.
    const glue = gluePadding(utf8(secret).length);
    expect(f.glueHex).toBe(glue.toString('hex'));
    expect(f.glueHex.startsWith('80')).toBe(true);
    expect((utf8(secret).length + glue.length) % 64).toBe(0);
    expect(f.glueHex.slice(-16)).toBe(
      (BigInt(utf8(secret).length) * 8n).toString(16).padStart(16, '0'),
    );

    // 3. The appended bytes are the attacker's.
    expect(f.appended).toBe(append);

    // 4/5. The forged tag equals the page's own from-scratch recompute AND an
    // independent one done here in node. This is the headline verdict.
    const reconstructed = Buffer.concat([Buffer.from(secret, 'utf8'), glue, Buffer.from(append, 'utf8')]);
    expect(f.forged).toBe(f.verify);
    expect(f.forged).toBe(nodeHash('sha256', reconstructed));

    // It is genuinely a forgery: not the tag of the honest message.
    expect(f.forged).not.toBe(f.publishedTag);
    expect(f.forged).not.toBe(nodeHash('sha256', secret + append));

    await expect(page.locator('#lext-result .lext-verdict')).toContainText('✓ VERIFIED');
    await expect(page.locator('.lext-bad')).toHaveCount(0);
  });

  test.describe('holds for secrets whose padding crosses a block boundary', () => {
    for (const secret of ['k', 'a'.repeat(55), 'b'.repeat(56), 'c'.repeat(63), 'd'.repeat(120)]) {
      test(`secret of ${utf8(secret).length} bytes`, async ({ page }) => {
        const append = '|payload';
        await page.locator('#lext-secret').fill(secret);
        await page.locator('#lext-append').fill(append);
        await page.locator('#lext-btn').click();

        const f = await readForgery(page);
        const glue = gluePadding(utf8(secret).length);
        expect(f.reportedLen).toBe(utf8(secret).length);
        expect(f.glueHex).toBe(glue.toString('hex'));
        const reconstructed = Buffer.concat([
          Buffer.from(secret, 'utf8'),
          glue,
          Buffer.from(append, 'utf8'),
        ]);
        expect(f.forged).toBe(nodeHash('sha256', reconstructed));
        expect(f.forged).toBe(f.verify);
        await expect(page.locator('#lext-result .lext-verdict')).toContainText('✓ VERIFIED');
        await expect(page.locator('#aria-live-region')).toHaveText(
          'Length extension succeeded: the forged SHA-256 tag validates against the reconstructed message.',
        );
      });
    }
  });

  test('an empty append still forges a valid tag', async ({ page }) => {
    await page.locator('#lext-append').fill('');
    await page.locator('#lext-btn').click();
    const f = await readForgery(page);
    const secret = 'secret-key||user=alice&role=guest';
    const reconstructed = Buffer.concat([
      Buffer.from(secret, 'utf8'),
      gluePadding(utf8(secret).length),
    ]);
    expect(f.forged).toBe(nodeHash('sha256', reconstructed));
    expect(f.forged).toBe(f.verify);
  });

  test('FAILURE PATH: an empty secret refuses to forge and says why (screen readers too)', async ({
    page,
  }) => {
    await page.locator('#lext-secret').fill('');
    await page.locator('#lext-btn').click();
    await expect(page.locator('#lext-result')).toHaveText(
      'Enter a non-empty secret to run the forgery.',
    );
    await expect(page.locator('#lext-result .lext-verdict')).toHaveCount(0);
    // REGRESSION: this used to announce "Length extension succeeded", because
    // the announcement re-ran the attack with a substituted secret ('x') that
    // the user never entered, while the panel showed the refusal above.
    await expect(page.locator('#aria-live-region')).toHaveText(
      'Enter a non-empty secret to run the forgery.',
    );
  });

  test('TAMPER PATH: attacker-controlled append is escaped, never executed', async ({ page }) => {
    const payload = '<img src=x onerror="window.__pwned = 1">';
    await page.locator('#lext-append').fill(payload);
    await page.locator('#lext-btn').click();

    const f = await readForgery(page);
    expect(f.appended).toBe(payload);
    await expect(page.locator('#lext-result img')).toHaveCount(0);
    expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();

    // The escaped markup is still hashed as its literal bytes.
    const secret = 'secret-key||user=alice&role=guest';
    const reconstructed = Buffer.concat([
      Buffer.from(secret, 'utf8'),
      gluePadding(utf8(secret).length),
      Buffer.from(payload, 'utf8'),
    ]);
    expect(f.forged).toBe(nodeHash('sha256', reconstructed));
  });
});

// ---------------------------------------------------------------------------
// Padding modal.
// ---------------------------------------------------------------------------

test.describe('Padding info', () => {
  test('shows the real SHA-256 padded block and a 1600-bit sponge split', async ({ page }) => {
    const message = 'pad me';
    await setMessage(page, message);
    await page.locator('#padding-btn').click();
    const modal = page.locator('#padding-modal');
    await expect(modal).toBeVisible();

    const text = (await page.locator('#padding-content').textContent()) ?? '';
    const paddedHex = /SHA-256 padded block hex:\n([0-9a-f]+)/.exec(text)?.[1] ?? '';
    const bytes = utf8(message);

    // Merkle-Damgard padding: message, 0x80 marker, zero fill to a whole number
    // of 512-bit blocks, big-endian bit length in the final 8 bytes.
    expect(paddedHex.length % 128).toBe(0);
    expect(paddedHex.startsWith(Buffer.from(bytes).toString('hex'))).toBe(true);
    expect(paddedHex.slice(bytes.length * 2, bytes.length * 2 + 2)).toBe('80');
    expect(paddedHex.slice(-16)).toBe((BigInt(bytes.length) * 8n).toString(16).padStart(16, '0'));
    const middle = paddedHex.slice(bytes.length * 2 + 2, -16);
    expect(middle).toMatch(/^0*$/);

    // Sponge: the rate and capacity quoted here must sum to Keccak's 1600-bit
    // state — the same split the Section C diagram and info panel claim.
    const rate = Number(/SHA-3 rate: (\d+) bits/.exec(text)?.[1]);
    const capacity = Number(/SHA-3 capacity: (\d+) bits/.exec(text)?.[1]);
    expect(rate).toBe(1088);
    expect(capacity).toBe(512);
    expect(rate + capacity).toBe(1600);

    await page.locator('#close-modal').click();
    await expect(modal).toBeHidden();
  });

  test('the padded block of an empty message is one full 512-bit block', async ({ page }) => {
    await setMessage(page, '');
    await page.locator('#padding-btn').click();
    const text = (await page.locator('#padding-content').textContent()) ?? '';
    const paddedHex = /SHA-256 padded block hex:\n([0-9a-f]+)/.exec(text)?.[1] ?? '';
    expect(paddedHex).toBe('80'.padEnd(128, '0'));
    await page.locator('#close-modal').click();
  });
});

// ---------------------------------------------------------------------------
// Info panel tabs.
// ---------------------------------------------------------------------------

test.describe('Info panel', () => {
  test('each tab reveals exactly its own panel, by click and by keyboard', async ({ page }) => {
    const pairs = [
      ['tab-md', 'panel-md'],
      ['tab-sponge', 'panel-sponge'],
      ['tab-tree', 'panel-tree'],
      ['tab-choose', 'panel-choose'],
    ];

    for (const [tab, panel] of pairs) {
      await page.locator(`#${tab}`).click();
      await expect(page.locator('.tab-panel.is-active')).toHaveCount(1);
      await expect(page.locator('.tab-panel.is-active')).toHaveAttribute('id', panel);
      await expect(page.locator(`#${tab}`)).toHaveAttribute('aria-selected', 'true');
      await expect(page.locator('.tab[aria-selected="true"]')).toHaveCount(1);
    }

    await page.locator('#tab-md').click();
    await page.keyboard.press('ArrowRight');
    await expect(page.locator('.tab-panel.is-active')).toHaveAttribute('id', 'panel-sponge');
    await page.keyboard.press('End');
    await expect(page.locator('.tab-panel.is-active')).toHaveAttribute('id', 'panel-choose');
    await page.keyboard.press('Home');
    await expect(page.locator('.tab-panel.is-active')).toHaveAttribute('id', 'panel-md');
    await page.keyboard.press('ArrowLeft');
    await expect(page.locator('.tab-panel.is-active')).toHaveAttribute('id', 'panel-choose');
  });

  test('the sponge panel states the rate/capacity split the padding modal computes', async ({
    page,
  }) => {
    await page.locator('#tab-sponge').click();
    const panel = page.locator('#panel-sponge');
    await expect(panel).toContainText('1088');
    await expect(panel).toContainText('512');
  });
});
