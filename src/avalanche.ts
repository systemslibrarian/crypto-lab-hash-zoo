const decoder = new TextDecoder();
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

  const originalChar = decoder.decode(bytes.slice(byteIndex, byteIndex + 1)) || '\\u0000';
  const modifiedChar = decoder.decode(modified.slice(byteIndex, byteIndex + 1)) || '\\u0000';

  return {
    charIndex: byteIndex,
    bitOffsetInChar,
    originalChar,
    modifiedChar,
    summary: `Flipping bit ${bitPosition} (byte ${byteIndex}, bit ${bitOffsetInChar}) changes '${originalChar}' -> '${modifiedChar}'.`,
  };
}
