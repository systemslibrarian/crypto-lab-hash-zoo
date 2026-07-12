import { blake3 } from '@noble/hashes/blake3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

export interface HashDetail {
  hex: string;
  bytes: Uint8Array;
  timeMs: number;
}

export interface HashResults {
  sha256: HashDetail;
  sha3: HashDetail;
  blake3: HashDetail;
}

export interface AvalanchePerAlgorithm {
  originalHash: string;
  flippedHash: string;
  diffBits: number;
  diffPercent: number;
  changedBitMap: boolean[];
}

export interface AvalancheResult {
  flippedInputHex: string;
  bitPosition: number;
  sha256: AvalanchePerAlgorithm;
  sha3: AvalanchePerAlgorithm;
  blake3: AvalanchePerAlgorithm;
}

export interface PaddingResult {
  sha256Padding: string;
  sha3Rate: number;
  sha3Capacity: number;
}

const ITERATIONS = 100;
const HASH_BITS = 256;

const encoder = new TextEncoder();

function avgTimedHash(input: Uint8Array, fn: (message: Uint8Array) => Uint8Array): HashDetail {
  let output = fn(input);
  const start = performance.now();
  for (let i = 0; i < ITERATIONS; i += 1) {
    output = fn(input);
  }
  const elapsed = performance.now() - start;

  return {
    hex: bytesToHex(output),
    bytes: output,
    timeMs: elapsed / ITERATIONS,
  };
}

export function popcount(byte: number): number {
  let value = byte;
  let count = 0;
  while (value !== 0) {
    value &= value - 1;
    count += 1;
  }
  return count;
}

export function diffBitmap(a: Uint8Array, b: Uint8Array): { changedBitMap: boolean[]; diffBits: number } {
  const changedBitMap = new Array<boolean>(HASH_BITS).fill(false);
  let diffBits = 0;

  for (let byteIndex = 0; byteIndex < a.length; byteIndex += 1) {
    const xorByte = a[byteIndex] ^ b[byteIndex];
    diffBits += popcount(xorByte);

    for (let bit = 0; bit < 8; bit += 1) {
      const bitIndex = byteIndex * 8 + bit;
      changedBitMap[bitIndex] = ((xorByte >> (7 - bit)) & 1) === 1;
    }
  }

  return { changedBitMap, diffBits };
}

export function flipBit(input: Uint8Array, bitPosition: number): Uint8Array {
  if (input.length === 0) {
    throw new Error('Cannot flip bits in an empty message.');
  }

  if (bitPosition < 0 || bitPosition >= input.length * 8) {
    throw new Error(`Bit position ${bitPosition} out of range.`);
  }

  const clone = input.slice();
  const byteIndex = Math.floor(bitPosition / 8);
  const bitOffset = bitPosition % 8;
  clone[byteIndex] ^= 1 << (7 - bitOffset);
  return clone;
}

function analyzePair(original: Uint8Array, changed: Uint8Array): AvalanchePerAlgorithm {
  const { changedBitMap, diffBits } = diffBitmap(original, changed);
  return {
    originalHash: bytesToHex(original),
    flippedHash: bytesToHex(changed),
    diffBits,
    diffPercent: (diffBits / HASH_BITS) * 100,
    changedBitMap,
  };
}

/**
 * The three hash functions the zoo compares, exported so tests can assert the
 * wiring against known-answer test vectors. A swapped or renamed import would
 * change these digests and fail the KAT suite instead of shipping silently.
 */
export const HASH_FUNCTIONS: Record<'sha256' | 'sha3' | 'blake3', (message: Uint8Array) => Uint8Array> = {
  sha256,
  sha3: sha3_256,
  blake3,
};

/** Pure digests with no timing, for testing and reuse. */
export function digestAll(message: string): Record<'sha256' | 'sha3' | 'blake3', string> {
  const messageBytes = encoder.encode(message);
  return {
    sha256: bytesToHex(HASH_FUNCTIONS.sha256(messageBytes)),
    sha3: bytesToHex(HASH_FUNCTIONS.sha3(messageBytes)),
    blake3: bytesToHex(HASH_FUNCTIONS.blake3(messageBytes)),
  };
}

export function hashAll(message: string): HashResults {
  const messageBytes = encoder.encode(message);
  return {
    sha256: avgTimedHash(messageBytes, HASH_FUNCTIONS.sha256),
    sha3: avgTimedHash(messageBytes, HASH_FUNCTIONS.sha3),
    blake3: avgTimedHash(messageBytes, HASH_FUNCTIONS.blake3),
  };
}

export function avalancheAnalysis(message: string, bitPosition: number): AvalancheResult {
  const originalBytes = encoder.encode(message);
  const flippedBytes = flipBit(originalBytes, bitPosition);

  const sha256Original = sha256(originalBytes);
  const sha256Flipped = sha256(flippedBytes);

  const sha3Original = sha3_256(originalBytes);
  const sha3Flipped = sha3_256(flippedBytes);

  const blake3Original = blake3(originalBytes);
  const blake3Flipped = blake3(flippedBytes);

  return {
    flippedInputHex: bytesToHex(flippedBytes),
    bitPosition,
    sha256: analyzePair(sha256Original, sha256Flipped),
    sha3: analyzePair(sha3Original, sha3Flipped),
    blake3: analyzePair(blake3Original, blake3Flipped),
  };
}

export function paddingInfo(message: string): PaddingResult {
  const messageBytes = encoder.encode(message);
  const bitLength = BigInt(messageBytes.length * 8);

  const padded: number[] = [...messageBytes, 0x80];
  while ((padded.length % 64) !== 56) {
    padded.push(0x00);
  }

  for (let i = 7; i >= 0; i -= 1) {
    const shift = BigInt(i * 8);
    padded.push(Number((bitLength >> shift) & 0xffn));
  }

  return {
    sha256Padding: bytesToHex(Uint8Array.from(padded)),
    sha3Rate: 1088,
    sha3Capacity: 512,
  };
}
