const encoder = new TextEncoder();

export interface BitFlipLabel {
  charIndex: number;
  bitOffsetInChar: number;
  originalChar: string;
  modifiedChar: string;
  summary: string;
}

export function maxBitPosition(message: string): number {
  return Math.max(0, encoder.encode(message).length * 8 - 1);
}

export interface InputBitStrip {
  /** One entry per input bit: its value (0/1) and whether it is the flipped one. */
  bits: { value: 0 | 1; flipped: boolean }[];
  totalBits: number;
  /** Index of the flipped bit within `bits`, or -1 when empty. */
  flippedIndex: number;
}

/**
 * Expand the message to a bit strip (MSB-first per byte) so the UI can show the
 * single toggled input bit right next to the 256-bit output storm. Capped so a
 * huge paste doesn't render tens of thousands of cells.
 */
export function inputBitStrip(message: string, bitPosition: number, maxBits = 512): InputBitStrip {
  const bytes = encoder.encode(message);
  const totalBits = bytes.length * 8;
  const shown = Math.min(totalBits, maxBits);
  const bits: { value: 0 | 1; flipped: boolean }[] = [];
  for (let i = 0; i < shown; i += 1) {
    const byteIndex = Math.floor(i / 8);
    const bitOffset = i % 8;
    const value = ((bytes[byteIndex] >> (7 - bitOffset)) & 1) as 0 | 1;
    bits.push({ value, flipped: i === bitPosition });
  }
  return {
    bits,
    totalBits,
    flippedIndex: totalBits === 0 ? -1 : bitPosition,
  };
}

export function describeBitFlip(message: string, bitPosition: number): BitFlipLabel {
  const bytes = encoder.encode(message);
  if (bytes.length === 0) {
    return {
      charIndex: 0,
      bitOffsetInChar: 0,
      originalChar: '(empty)',
      modifiedChar: '(empty)',
      summary: 'Message is empty, add at least one character to run avalanche analysis.',
    };
  }

  const byteIndex = Math.floor(bitPosition / 8);
  const bitOffsetInChar = bitPosition % 8;
  const modified = bytes.slice();
  modified[byteIndex] ^= 1 << (7 - bitOffsetInChar);

  const originalHex = bytes[byteIndex].toString(16).padStart(2, '0');
  const modifiedHex = modified[byteIndex].toString(16).padStart(2, '0');

  return {
    charIndex: byteIndex,
    bitOffsetInChar,
    originalChar: `0x${originalHex}`,
    modifiedChar: `0x${modifiedHex}`,
    summary: `Flipping bit ${bitPosition} (byte ${byteIndex}, bit ${bitOffsetInChar}) changes byte 0x${originalHex} -> 0x${modifiedHex}.`,
  };
}
