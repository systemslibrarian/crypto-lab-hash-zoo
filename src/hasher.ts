import { blake3 } from '@noble/hashes/blake3.js';
import { sha256, _SHA256 } from '@noble/hashes/sha2.js';
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

// ---------------------------------------------------------------------------
// One-line "what is a hash?" example, kept spec-accurate (real digest, short-
// ened for display only — the full hex is always available too).
// ---------------------------------------------------------------------------

export interface OneLineHash {
  full: string;
  short: string;
}

/** SHA-256 of a short demo string, for the intro "what is a hash" block. */
export function oneLineHash(message: string): OneLineHash {
  const full = bytesToHex(sha256(encoder.encode(message)));
  return { full, short: `${full.slice(0, 12)}…${full.slice(-8)}` };
}

// ---------------------------------------------------------------------------
// Length-extension demonstration (real attack, not a mock).
//
// Bare Merkle-Damgard hashes publish their entire internal state as the digest.
// An attacker who knows H(secret) and len(secret) — but NOT the secret bytes —
// can resume the compression function from that published state, append their
// own data, and emit a hash that validates against secret || glue || append.
//
// We prove the forgery honestly: `forgedHash` is computed by resuming state,
// while `verifyHash` recomputes sha256 over the fully reconstructed message
// from scratch. They MUST be equal, and `verified` asserts it at runtime.
// ---------------------------------------------------------------------------

export interface LengthExtensionResult {
  /** Digest of the original secret (all the attacker legitimately holds). */
  originalDigest: string;
  /** Length in bytes of the original secret (the one other fact required). */
  originalLen: number;
  /** The glue padding Merkle-Damgard appended after the secret, as hex. */
  gluePaddingHex: string;
  /** The bytes the attacker appends, as text. */
  appended: string;
  /** Forged digest produced by resuming from originalDigest (attack path). */
  forgedHash: string;
  /** sha256 of the reconstructed message, computed from scratch (proof path). */
  verifyHash: string;
  /** True when forgedHash === verifyHash: the forgery is a valid SHA-256. */
  verified: boolean;
  /** Reconstructed forged message as hex (secret || glue || append). */
  forgedMessageHex: string;
}

/**
 * The glue padding SHA-256 appends after a message of `msgLen` bytes: the 0x80
 * marker, zero fill to a 56 mod 64 boundary, then the 64-bit big-endian bit
 * length. This is exactly what the original hasher already absorbed, so the
 * attacker's continuation lines up on a block boundary.
 */
export function sha256GluePadding(msgLen: number): Uint8Array {
  const bitLen = BigInt(msgLen * 8);
  const out: number[] = [0x80];
  while ((msgLen + out.length) % 64 !== 56) {
    out.push(0x00);
  }
  for (let i = 7; i >= 0; i -= 1) {
    out.push(Number((bitLen >> BigInt(i * 8)) & 0xffn));
  }
  return Uint8Array.from(out);
}

/**
 * Perform a real SHA-256 length-extension forgery from a published digest.
 * The attacker never sees `secret` bytes here except to reconstruct the proof;
 * the forged digest itself is derived solely from `originalDigest` + length.
 */
export function lengthExtend(secret: string, append: string): LengthExtensionResult {
  const secretBytes = encoder.encode(secret);
  const appendBytes = encoder.encode(append);
  const originalDigest = sha256(secretBytes);

  // --- Attack path: resume from the published digest, knowing only its length.
  const resumed = new _SHA256() as unknown as {
    set(...words: number[]): void;
    length: number;
    update(data: Uint8Array): unknown;
    digest(): Uint8Array;
  };
  const dv = new DataView(originalDigest.buffer, originalDigest.byteOffset, originalDigest.byteLength);
  const words: number[] = [];
  for (let i = 0; i < 8; i += 1) {
    words.push(dv.getUint32(i * 4, false));
  }
  resumed.set(...words);
  const glue = sha256GluePadding(secretBytes.length);
  // Bytes the original hash already consumed = secret + its glue padding.
  resumed.length = secretBytes.length + glue.length;
  resumed.update(appendBytes);
  const forgedHash = bytesToHex(resumed.digest());

  // --- Proof path: rebuild the full message and hash it from scratch.
  const forgedMessage = new Uint8Array(secretBytes.length + glue.length + appendBytes.length);
  forgedMessage.set(secretBytes, 0);
  forgedMessage.set(glue, secretBytes.length);
  forgedMessage.set(appendBytes, secretBytes.length + glue.length);
  const verifyHash = bytesToHex(sha256(forgedMessage));

  return {
    originalDigest: bytesToHex(originalDigest),
    originalLen: secretBytes.length,
    gluePaddingHex: bytesToHex(glue),
    appended: append,
    forgedHash,
    verifyHash,
    verified: forgedHash === verifyHash,
    forgedMessageHex: bytesToHex(forgedMessage),
  };
}

// ---------------------------------------------------------------------------
// Avalanche distribution: flip every input bit in turn and collect the
// per-flip output-diff percentage for one algorithm. Shows that ~50% is a
// statistical law, not one lucky flip.
// ---------------------------------------------------------------------------

export interface AvalancheDistribution {
  percents: number[];
  mean: number;
  min: number;
  max: number;
  /** Histogram bucket counts across [0,100] in `buckets.length` bins. */
  buckets: number[];
  bucketSize: number;
}

const DIST_MAX_BITS = 4096; // cap work: sample at most this many input bits

export function avalancheDistribution(
  message: string,
  algo: 'sha256' | 'sha3' | 'blake3',
  bucketCount = 20,
): AvalancheDistribution {
  const fn = HASH_FUNCTIONS[algo];
  const bytes = encoder.encode(message);
  const totalBits = bytes.length * 8;
  const buckets = new Array<number>(bucketCount).fill(0);
  const bucketSize = 100 / bucketCount;
  const percents: number[] = [];
  if (totalBits === 0) {
    return { percents, mean: 0, min: 0, max: 0, buckets, bucketSize };
  }

  const original = fn(bytes);
  // Even sampling if the message is large, otherwise every bit.
  const step = totalBits > DIST_MAX_BITS ? Math.ceil(totalBits / DIST_MAX_BITS) : 1;
  let sum = 0;
  let min = 100;
  let max = 0;
  for (let pos = 0; pos < totalBits; pos += step) {
    const flipped = flipBit(bytes, pos);
    const { diffBits } = diffBitmap(original, fn(flipped));
    const pct = (diffBits / HASH_BITS) * 100;
    percents.push(pct);
    sum += pct;
    if (pct < min) min = pct;
    if (pct > max) max = pct;
    const bucket = Math.min(bucketCount - 1, Math.floor(pct / bucketSize));
    buckets[bucket] += 1;
  }

  return {
    percents,
    mean: sum / percents.length,
    min,
    max,
    buckets,
    bucketSize,
  };
}
