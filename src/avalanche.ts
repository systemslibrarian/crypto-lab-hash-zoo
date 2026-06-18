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
