import { describe, it, expect } from 'vitest';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  digestAll,
  hashAll,
  avalancheAnalysis,
  paddingInfo,
  popcount,
  diffBitmap,
  flipBit,
  HASH_FUNCTIONS,
} from './hasher';

const enc = new TextEncoder();

/**
 * Known-answer test vectors from the published standards, NOT re-derived from
 * @noble at runtime. If a source import were swapped (e.g. sha3 -> sha256) the
 * digests below would no longer match and these tests would fail instead of
 * the demo shipping a mislabelled algorithm silently.
 *
 *   SHA-256   : FIPS 180-4
 *   SHA3-256  : FIPS 202
 *   BLAKE3    : BLAKE3 reference test vectors
 */
const KAT = {
  '': {
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    sha3: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    blake3: 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
  },
  abc: {
    sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    sha3: '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    blake3: '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85',
  },
} as const;

describe('known-answer test vectors (catches a swapped algorithm import)', () => {
  for (const [message, expected] of Object.entries(KAT)) {
    it(`digestAll(${JSON.stringify(message)}) matches published vectors`, () => {
      expect(digestAll(message)).toEqual(expected);
    });

    it(`hashAll(${JSON.stringify(message)}) hex matches digestAll and KAT`, () => {
      const results = hashAll(message);
      expect(results.sha256.hex).toBe(expected.sha256);
      expect(results.sha3.hex).toBe(expected.sha3);
      expect(results.blake3.hex).toBe(expected.blake3);
    });
  }

  it('each of the three algorithms is distinct (not the same function under different labels)', () => {
    const d = digestAll('avalanche');
    expect(d.sha256).not.toBe(d.sha3);
    expect(d.sha256).not.toBe(d.blake3);
    expect(d.sha3).not.toBe(d.blake3);
  });

  it('HASH_FUNCTIONS.sha256 actually produces the SHA-256 KAT', () => {
    expect(bytesToHex(HASH_FUNCTIONS.sha256(enc.encode('abc')))).toBe(KAT.abc.sha256);
  });
});

describe('determinism and output shape', () => {
  it('same input always yields the same digest', () => {
    expect(digestAll('The quick brown fox')).toEqual(digestAll('The quick brown fox'));
  });

  it('every digest is exactly 256 bits (64 hex chars)', () => {
    const d = digestAll('The quick brown fox jumps over the lazy dog');
    for (const hex of Object.values(d)) {
      expect(hex).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('hashAll reports a non-negative average time per algorithm', () => {
    const results = hashAll('timing');
    for (const detail of [results.sha256, results.sha3, results.blake3]) {
      expect(detail.timeMs).toBeGreaterThanOrEqual(0);
      expect(Number.isFinite(detail.timeMs)).toBe(true);
    }
  });
});

describe('popcount', () => {
  it('counts set bits for every byte value 0..255', () => {
    for (let b = 0; b < 256; b += 1) {
      const expected = b.toString(2).split('').filter((c) => c === '1').length;
      expect(popcount(b)).toBe(expected);
    }
  });
});

describe('flipBit', () => {
  it('flips exactly one bit (Hamming distance 1 from the original)', () => {
    const input = enc.encode('hello world');
    for (let pos = 0; pos < input.length * 8; pos += 1) {
      const flipped = flipBit(input, pos);
      let diff = 0;
      for (let i = 0; i < input.length; i += 1) {
        diff += popcount(input[i] ^ flipped[i]);
      }
      expect(diff).toBe(1);
    }
  });

  it('does not mutate the input array', () => {
    const input = enc.encode('immutable');
    const copy = input.slice();
    flipBit(input, 3);
    expect(Array.from(input)).toEqual(Array.from(copy));
  });

  it('flips the most-significant bit first (bit 0 -> 0x80 mask)', () => {
    const input = Uint8Array.of(0x00);
    expect(flipBit(input, 0)[0]).toBe(0x80);
    expect(flipBit(input, 7)[0]).toBe(0x01);
  });

  it('throws on empty message and out-of-range positions', () => {
    expect(() => flipBit(new Uint8Array(0), 0)).toThrow();
    expect(() => flipBit(enc.encode('a'), 8)).toThrow();
    expect(() => flipBit(enc.encode('a'), -1)).toThrow();
  });
});

describe('diffBitmap', () => {
  it('reports zero differences for identical arrays', () => {
    const a = enc.encode('same');
    const { diffBits, changedBitMap } = diffBitmap(a, a.slice());
    expect(diffBits).toBe(0);
    expect(changedBitMap.every((c) => c === false)).toBe(true);
  });

  it('changedBitMap length is always 256 and diffBits matches the true count', () => {
    const a = new Uint8Array(32).fill(0x00);
    const b = new Uint8Array(32).fill(0xff);
    const { diffBits, changedBitMap } = diffBitmap(a, b);
    expect(changedBitMap).toHaveLength(256);
    expect(diffBits).toBe(256);
    expect(changedBitMap.every((c) => c === true)).toBe(true);
  });

  it('locates the changed bit in MSB-first order', () => {
    const a = Uint8Array.of(0x00);
    const b = Uint8Array.of(0x80); // top bit set
    const { changedBitMap, diffBits } = diffBitmap(a, b);
    expect(diffBits).toBe(1);
    expect(changedBitMap[0]).toBe(true);
    expect(changedBitMap[1]).toBe(false);
  });
});

describe('avalanche effect (~50% of output bits flip on a 1-bit input change)', () => {
  const algorithms = ['sha256', 'sha3', 'blake3'] as const;

  it('flipping one input bit changes close to half the output bits for every algorithm', () => {
    const message = 'The quick brown fox jumps over the lazy dog';
    const bitCount = message.length * 8;

    // Average avalanche across many single-bit flips to smooth per-position noise.
    const totals: Record<(typeof algorithms)[number], number> = { sha256: 0, sha3: 0, blake3: 0 };
    const samples = 40;
    for (let s = 0; s < samples; s += 1) {
      const pos = Math.floor((s / samples) * bitCount);
      const result = avalancheAnalysis(message, pos);
      for (const algo of algorithms) {
        totals[algo] += result[algo].diffPercent;
      }
    }

    for (const algo of algorithms) {
      const avg = totals[algo] / samples;
      // A strong hash flips ~50% of bits; require the average within [42, 58]%.
      expect(avg).toBeGreaterThan(42);
      expect(avg).toBeLessThan(58);
    }
  });

  it('the flipped input differs from the original by exactly one bit', () => {
    const message = 'avalanche';
    const original = enc.encode(message);
    const result = avalancheAnalysis(message, 5);
    const flipped = Uint8Array.from(
      (result.flippedInputHex.match(/.{2}/g) ?? []).map((h) => parseInt(h, 16)),
    );
    let diff = 0;
    for (let i = 0; i < original.length; i += 1) {
      diff += popcount(original[i] ^ flipped[i]);
    }
    expect(diff).toBe(1);
  });

  it('diffPercent is consistent with diffBits over 256 output bits', () => {
    const result = avalancheAnalysis('consistency', 3);
    for (const algo of algorithms) {
      const pair = result[algo];
      expect(pair.diffPercent).toBeCloseTo((pair.diffBits / 256) * 100, 6);
      expect(pair.changedBitMap.filter(Boolean)).toHaveLength(pair.diffBits);
    }
  });
});

describe('paddingInfo', () => {
  it('reports the standard SHA-3 (SHA3-256) rate and capacity', () => {
    const info = paddingInfo('anything');
    expect(info.sha3Rate).toBe(1088);
    expect(info.sha3Capacity).toBe(512);
    // Keccak-f[1600]: rate + capacity = full state width.
    expect(info.sha3Rate + info.sha3Capacity).toBe(1600);
  });

  it('produces SHA-256 Merkle-Damgard padding: 0x80 marker, block-aligned, correct bit-length tail', () => {
    const message = 'abc';
    const info = paddingInfo(message);
    const padded = Uint8Array.from(
      (info.sha256Padding.match(/.{2}/g) ?? []).map((h) => parseInt(h, 16)),
    );

    // Message bytes preserved at the front.
    expect(Array.from(padded.slice(0, 3))).toEqual(Array.from(enc.encode(message)));
    // 0x80 marker immediately after the message.
    expect(padded[3]).toBe(0x80);
    // Padded length is a whole number of 512-bit (64-byte) blocks.
    expect(padded.length % 64).toBe(0);
    // Final 64 bits encode the message length in bits, big-endian.
    const tail = padded.slice(padded.length - 8);
    const bitLen = tail.reduce((acc, byte) => acc * 256n + BigInt(byte), 0n);
    expect(bitLen).toBe(BigInt(message.length * 8));
  });
});
