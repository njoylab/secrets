/**
 * QR encoder tests.
 *
 * The encoder is verified by decoding its output back. A decoder lives in this
 * file only: it walks the symbol the way a scanner does (read the format
 * information, undo the mask, read the zigzag, de-interleave, strip the header)
 * and checks the Reed-Solomon syndromes, so a mistake anywhere in the encoding
 * path shows up as a failing assertion rather than as a code no phone can read.
 *
 * The decoder is first pinned against `qrcode-generator`, a dev-only oracle
 * whose own output must decode to the original text. Only once the decoder has
 * proved itself on foreign symbols is it pointed at ours.
 */
import { describe, expect, it } from 'vitest';
import qrcode from 'qrcode-generator';
import { encodeQr, QrCapacityError, qrToSvg, qrToSvgPath } from '../src/lib/qr.ts';

type Ecc = 'L' | 'M' | 'Q' | 'H';

const ECC_ORDER: Record<Ecc, number> = { L: 0, M: 1, Q: 2, H: 3 };
const ECC_FROM_FORMAT: Record<number, Ecc> = { 1: 'L', 0: 'M', 3: 'Q', 2: 'H' };

const RS_BLOCK_TABLE = [
  [[7, 1, 19], [10, 1, 16], [13, 1, 13], [17, 1, 9]],
  [[10, 1, 34], [16, 1, 28], [22, 1, 22], [28, 1, 16]],
  [[15, 1, 55], [26, 1, 44], [18, 2, 17], [22, 2, 13]],
  [[20, 1, 80], [18, 2, 32], [26, 2, 24], [16, 4, 9]],
  [[26, 1, 108], [24, 2, 43], [18, 2, 15, 2, 16], [22, 2, 11, 2, 12]],
  [[18, 2, 68], [16, 4, 27], [24, 4, 19], [28, 4, 15]],
  [[20, 2, 78], [18, 4, 31], [18, 2, 14, 4, 15], [26, 4, 13, 1, 14]],
  [[24, 2, 97], [22, 2, 38, 2, 39], [22, 4, 18, 2, 19], [26, 4, 14, 2, 15]],
  [[30, 2, 116], [22, 3, 36, 2, 37], [20, 4, 16, 4, 17], [24, 4, 12, 4, 13]],
  [[18, 2, 68, 2, 69], [26, 4, 43, 1, 44], [24, 6, 19, 2, 20], [28, 6, 15, 2, 16]],
  [[20, 4, 81], [30, 1, 50, 4, 51], [28, 4, 22, 4, 23], [24, 3, 12, 8, 13]],
  [[24, 2, 92, 2, 93], [22, 6, 36, 2, 37], [26, 4, 20, 6, 21], [28, 7, 14, 4, 15]],
  [[26, 4, 107], [22, 8, 37, 1, 38], [24, 8, 20, 4, 21], [22, 12, 11, 4, 12]],
  [[30, 3, 115, 1, 116], [24, 4, 40, 5, 41], [20, 11, 16, 5, 17], [24, 11, 12, 5, 13]],
  [[22, 5, 87, 1, 88], [24, 5, 41, 5, 42], [30, 5, 24, 7, 25], [24, 11, 12, 7, 13]],
  [[24, 5, 98, 1, 99], [28, 7, 45, 3, 46], [24, 15, 19, 2, 20], [30, 3, 15, 13, 16]],
  [[28, 1, 107, 5, 108], [28, 10, 46, 1, 47], [28, 1, 22, 15, 23], [28, 2, 14, 17, 15]],
  [[30, 5, 120, 1, 121], [26, 9, 43, 4, 44], [28, 17, 22, 1, 23], [28, 2, 14, 19, 15]],
  [[28, 3, 113, 4, 114], [26, 3, 44, 11, 45], [26, 17, 21, 4, 22], [26, 9, 13, 16, 14]],
  [[28, 3, 107, 5, 108], [26, 3, 41, 13, 42], [30, 15, 24, 5, 25], [28, 15, 15, 10, 16]],
  [[28, 4, 116, 4, 117], [26, 17, 42], [28, 17, 22, 6, 23], [30, 19, 16, 6, 17]],
  [[28, 2, 111, 7, 112], [28, 17, 46], [30, 7, 24, 16, 25], [24, 34, 13]],
  [[30, 4, 121, 5, 122], [28, 4, 47, 14, 48], [30, 11, 24, 14, 25], [30, 16, 15, 14, 16]],
  [[30, 6, 117, 4, 118], [28, 6, 45, 14, 46], [30, 11, 24, 16, 25], [30, 30, 16, 2, 17]],
  [[26, 8, 106, 4, 107], [28, 8, 47, 13, 48], [30, 7, 24, 22, 25], [30, 22, 15, 13, 16]],
  [[28, 10, 114, 2, 115], [28, 19, 46, 4, 47], [28, 28, 22, 6, 23], [30, 33, 16, 4, 17]],
  [[30, 8, 122, 4, 123], [28, 22, 45, 3, 46], [30, 8, 23, 26, 24], [30, 12, 15, 28, 16]],
  [[30, 3, 117, 10, 118], [28, 3, 45, 23, 46], [30, 4, 24, 31, 25], [30, 11, 15, 31, 16]],
  [[30, 7, 116, 7, 117], [28, 21, 45, 7, 46], [30, 1, 23, 37, 24], [30, 19, 15, 26, 16]],
  [[30, 5, 115, 10, 116], [28, 19, 47, 10, 48], [30, 15, 24, 25, 25], [30, 23, 15, 25, 16]],
  [[30, 13, 115, 3, 116], [28, 2, 46, 29, 47], [30, 42, 24, 1, 25], [30, 23, 15, 28, 16]],
  [[30, 17, 115], [28, 10, 46, 23, 47], [30, 10, 24, 35, 25], [30, 19, 15, 35, 16]],
  [[30, 17, 115, 1, 116], [28, 14, 46, 21, 47], [30, 29, 24, 19, 25], [30, 11, 15, 46, 16]],
  [[30, 13, 115, 6, 116], [28, 14, 46, 23, 47], [30, 44, 24, 7, 25], [30, 59, 16, 1, 17]],
  [[30, 12, 121, 7, 122], [28, 12, 47, 26, 48], [30, 39, 24, 14, 25], [30, 22, 15, 41, 16]],
  [[30, 6, 121, 14, 122], [28, 6, 47, 34, 48], [30, 46, 24, 10, 25], [30, 2, 15, 64, 16]],
  [[30, 17, 122, 4, 123], [28, 29, 46, 14, 47], [30, 49, 24, 10, 25], [30, 24, 15, 46, 16]],
  [[30, 4, 122, 18, 123], [28, 13, 46, 32, 47], [30, 48, 24, 14, 25], [30, 42, 15, 32, 16]],
  [[30, 20, 117, 4, 118], [28, 40, 47, 7, 48], [30, 43, 24, 22, 25], [30, 10, 15, 67, 16]],
  [[30, 19, 118, 6, 119], [28, 18, 47, 31, 48], [30, 34, 24, 34, 25], [30, 20, 15, 61, 16]],
] as const;

/** Total codewords a version holds, before error correction is subtracted. */
const TOTAL_CODEWORDS = [
  0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655, 733, 815, 901,
  991, 1085, 1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185, 2323, 2465, 2611,
  2761, 2876, 3034, 3196, 3362, 3532, 3706,
] as const;

/** Unused modules left over after the codewords, per version. */
const REMAINDER_BITS = [
  0, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3,
  4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0,
] as const;

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let value = 1;
  for (let power = 0; power < 255; power += 1) {
    GF_EXP[power] = value;
    GF_LOG[value] = power;
    value <<= 1;
    if (value & 0x100) value ^= 0x11d;
  }
  for (let power = 255; power < 512; power += 1) GF_EXP[power] = GF_EXP[power - 255] as number;
}

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[(GF_LOG[a] as number) + (GF_LOG[b] as number)] as number;
}

function maskApplies(mask: number, row: number, column: number): boolean {
  switch (mask) {
    case 0:
      return (row + column) % 2 === 0;
    case 1:
      return row % 2 === 0;
    case 2:
      return column % 3 === 0;
    case 3:
      return (row + column) % 3 === 0;
    case 4:
      return (Math.floor(row / 2) + Math.floor(column / 3)) % 2 === 0;
    case 5:
      return ((row * column) % 2) + ((row * column) % 3) === 0;
    case 6:
      return (((row * column) % 2) + ((row * column) % 3)) % 2 === 0;
    default:
      return (((row + column) % 2) + ((row * column) % 3)) % 2 === 0;
  }
}

/** Dark-module lookup that mirrors the one the encoder uses, for its own asserts. */
function at(modules: readonly (readonly boolean[])[], row: number, column: number): boolean {
  return modules[row]?.[column] ?? false;
}

/** Centre coordinates of the alignment patterns, indexed by version minus one. */
const ALIGNMENTS: readonly (readonly number[])[] = [
  [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46],
  [6, 28, 50], [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70],
  [6, 26, 50, 74], [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90],
  [6, 28, 50, 72, 94], [6, 26, 50, 74, 98], [6, 30, 54, 78, 102], [6, 28, 54, 80, 106],
  [6, 32, 58, 84, 110], [6, 30, 58, 86, 114], [6, 34, 62, 90, 118], [6, 26, 50, 74, 98, 122],
  [6, 30, 54, 78, 102, 126], [6, 26, 52, 78, 104, 130], [6, 30, 56, 82, 108, 134],
  [6, 34, 60, 86, 112, 138], [6, 30, 58, 86, 114, 142], [6, 34, 62, 90, 118, 146],
  [6, 30, 54, 78, 102, 126, 150], [6, 24, 50, 76, 102, 128, 154], [6, 28, 54, 80, 106, 132, 158],
  [6, 32, 58, 84, 110, 136, 162], [6, 26, 54, 82, 110, 138, 166], [6, 30, 58, 86, 114, 142, 170],
];

/**
 * Every module the function patterns own, and so the data walk must skip.
 *
 * Derived from the size alone, the way a reader works it out: the finder
 * patterns and their separators take the corners, the timing patterns run
 * between them, the format information sits in two copies, and the alignment
 * patterns avoid the three corners the finders already hold.
 */
function reservedModules(size: number, version: number): boolean[][] {
  const reserved: boolean[][] = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const mark = (row: number, column: number): void => {
    if (row >= 0 && row < size && column >= 0 && column < size) {
      (reserved[row] as boolean[])[column] = true;
    }
  };
  for (const [top, left] of [[0, 0], [0, size - 7], [size - 7, 0]] as const) {
    for (let row = -1; row <= 7; row += 1) for (let column = -1; column <= 7; column += 1) mark(top + row, left + column);
  }
  // The timing patterns run between the finder patterns only: the modules they
  // would occupy inside the corners belong to a finder pattern and its separator.
  for (let index = 8; index < size - 8; index += 1) {
    mark(6, index);
    mark(index, 6);
  }
  mark(size - 8, 8);
  for (let index = 0; index <= 8; index += 1) {
    if (index !== 6) {
      mark(8, index);
      mark(index, 8);
    }
  }
  for (let index = 0; index < 8; index += 1) {
    mark(8, size - 1 - index);
    mark(size - 1 - index, 8);
  }
  if (version >= 7) {
    for (let index = 0; index < 18; index += 1) {
      const row = Math.floor(index / 3);
      const column = size - 11 + (index % 3);
      mark(row, column);
      mark(column, row);
    }
  }
  for (const row of ALIGNMENTS[version - 1] ?? []) {
    for (const column of ALIGNMENTS[version - 1] ?? []) {
      if (
        (row === 6 && column === 6) ||
        (row === 6 && column === size - 7) ||
        (row === size - 7 && column === 6)
      ) {
        continue;
      }
      for (let dr = -2; dr <= 2; dr += 1) for (let dc = -2; dc <= 2; dc += 1) mark(row + dr, column + dc);
    }
  }
  return reserved;
}

/**
 * The data and error correction bits in the order the zigzag visits them, with
 * the mask already undone.
 */
function unmaskedStream(modules: readonly (readonly boolean[])[], size: number, mask: number): number[] {
  const reserved = reservedModules(size, Math.floor((size - 17) / 4));
  const stream: number[] = [];
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step += 1) {
      const row = upward ? size - 1 - step : step;
      for (let offset = 0; offset < 2; offset += 1) {
        const column = right - offset;
        if (at(reserved, row, column)) continue;
        stream.push(at(modules, row, column) !== maskApplies(mask, row, column) ? 1 : 0);
      }
    }
    upward = !upward;
  }
  return stream;
}

interface Decoded {
  readonly version: number;
  readonly ecc: Ecc;
  readonly mask: number;
  readonly text: string;
}

/**
 * Read a symbol the way a scanner does.
 *
 * Every step is derived from the matrix alone, including the format
 * information, so the decoder shares no state with the encoder.
 */
function decodeSymbol(modules: readonly (readonly boolean[])[], size: number): Decoded {

  const read = (row: number, column: number): boolean => at(modules, row, column);

  // Format information: copy one, read from bit 14 downwards.
  let format = 0;
  const formatBit = (index: number): boolean => {
    if (index < 6) return read(index, 8);
    if (index === 6) return read(7, 8);
    if (index === 7) return read(8, 8);
    if (index === 8) return read(8, 7);
    return read(8, 14 - index);
  };
  for (let index = 0; index < 15; index += 1) {
    if (formatBit(index)) format |= 1 << index;
  }
  // Undo the XOR mask, then keep only the five data bits: the low bits of the
  // unmasked value are the BCH remainder, not payload.
  const data = (format ^ 0b101010000010010) >>> 10;
  const level = ECC_FROM_FORMAT[data >>> 3];
  const mask = data & 0b111;
  if (!level) throw new Error(`Unreadable format information: ${format.toString(2)}`);
  expect(mask).toBeGreaterThanOrEqual(0);
  expect(mask).toBeLessThan(8);

  const version = Math.floor((size - 17) / 4);
  if (version >= 7) {
    let versionBits = 0;
    for (let index = 0; index < 18; index += 1) {
      const row = Math.floor(index / 3);
      const column = size - 11 + (index % 3);
      if (read(row, column)) versionBits |= 1 << index;
    }
    // The BCH remainder must be zero for a valid symbol.
    let remainder = versionBits;
    for (let bit = 17; bit >= 12; bit -= 1) {
      if ((remainder >>> bit) & 1) remainder ^= 0b1111100100101 << (bit - 12);
    }
    expect(remainder & 0xfff).toBe(0);
  }

  const stream = unmaskedStream(modules, size, mask);

  const entry = (RS_BLOCK_TABLE[version - 1] as readonly (readonly number[])[])[ECC_ORDER[level]] as readonly number[];
  const ec = entry[0] as number;
  const blocks: { total: number; data: number; ec: number }[] = [];
  for (let index = 1; index < entry.length; index += 2) {
    const count = entry[index] as number;
    const data = entry[index + 1] as number;
    for (let made = 0; made < count; made += 1) {
      blocks.push({ total: data + ec, data, ec });
    }
  }

  const codewords = new Uint8Array(blocks.reduce((sum, block) => sum + block.total, 0));
  for (let index = 0; index < codewords.length; index += 1) {
    let byte = 0;
    for (let offset = 0; offset < 8; offset += 1) {
      byte = (byte << 1) | (stream[index * 8 + offset] as number);
    }
    codewords[index] = byte;
  }

  // De-interleave into blocks, then confirm every Reed-Solomon syndrome is zero:
  // that is the check that proves the error correction was built correctly.
  const dataBlocks: Uint8Array[] = blocks.map((block) => new Uint8Array(block.data));
  const ecBlocks: Uint8Array[] = blocks.map((block) => new Uint8Array(block.ec));
  const longestData = Math.max(...blocks.map((block) => block.data));
  const ecPerBlock = blocks[0]?.ec ?? 0;
  let cursor = 0;
  for (let index = 0; index < longestData; index += 1) {
    for (let block = 0; block < blocks.length; block += 1) {
      if (index < (blocks[block]?.data ?? 0)) {
        (dataBlocks[block] as Uint8Array)[index] = codewords[cursor++] as number;
      }
    }
  }
  for (let index = 0; index < ecPerBlock; index += 1) {
    for (let block = 0; block < blocks.length; block += 1) {
      (ecBlocks[block] as Uint8Array)[index] = codewords[cursor++] as number;
    }
  }
  blocks.forEach((block, index) => {
    const full = new Uint8Array(block.total);
    full.set(dataBlocks[index] as Uint8Array, 0);
    full.set(ecBlocks[index] as Uint8Array, block.data);
    // Evaluate the block as a polynomial at each root of the generator. Horner's
    // method, and the generator's roots are alpha^0..alpha^(ec-1), so a correct
    // block evaluates to zero everywhere.
    for (let root = 0; root < ec; root += 1) {
      let syndrome = 0;
      for (const value of full) syndrome = gfMul(syndrome, GF_EXP[root] as number) ^ value;
      expect(syndrome).toBe(0);
    }
  });

  const header = new Uint8Array(dataCodewords(dataBlocks));
  // Read the bit stream sequentially: the four mode bits are followed by the
  // length, which is not byte aligned, and then the payload.
  const bitAt = (position: number): number =>
    ((header[position >>> 3] as number) >>> (7 - (position & 7))) & 1;
  expect(((header[0] as number) >>> 4) & 0b1111).toBe(0b0100);
  const lengthBits = version <= 9 ? 8 : 16;
  let length = 0;
  for (let index = 0; index < lengthBits; index += 1) {
    length = (length << 1) | bitAt(4 + index);
  }
  const payloadStart = 4 + lengthBits;
  const payload: number[] = [];
  for (let index = 0; index < length * 8; index += 1) payload.push(bitAt(payloadStart + index));
  const text = new TextDecoder().decode(Uint8Array.from({ length }, (_, index) => {
    let byte = 0;
    for (let offset = 0; offset < 8; offset += 1) {
      byte = (byte << 1) | (payload[index * 8 + offset] as number);
    }
    return byte;
  }));
  return { version, ecc: level, mask, text };
}

/**
 * Put the data halves back into the order the encoder packed them in.
 *
 * The encoder interleaves across blocks, so undoing that means taking each
 * block's data codewords in full, one block after another, and concatenating
 * them. Blocks are laid out shortest first, which is why the result is the
 * original stream rather than a re-interleaving of it.
 */
function dataCodewords(blocks: readonly Uint8Array[]): Uint8Array {
  const output: number[] = [];
  for (const block of blocks) {
    for (const value of block) output.push(value);
  }
  return Uint8Array.from(output);
}

/**
 * Pull the matrix out of the oracle library so its output can be decoded.
 *
 * Byte mode is forced: this decoder only reads byte mode, and the oracle would
 * otherwise pick alphanumeric for an uppercase string, which would then fail
 * here for a reason that has nothing to do with the decoder.
 */
function oracleSymbol(text: string, version: number, ecc: Ecc): { modules: boolean[][]; size: number } {
  // The oracle types its first argument as its own version union, which the test
  // deliberately walks past, so the cast is the honest way to say so.
  const symbol = qrcode(version as 1, ecc);
  symbol.addData(text, 'Byte');
  symbol.make();
  const size = symbol.getModuleCount();
  const modules: boolean[][] = Array.from({ length: size }, (_, row) =>
    Array.from({ length: size }, (_, column) => symbol.isDark(row, column)),
  );
  return { modules, size };
}

describe('decoder oracle', () => {
  // If the decoder cannot read a known-good encoder, it cannot be trusted to
  // check ours either, so this runs first and pins the whole verification path.
  it('reads back symbols produced by an independent encoder', () => {
    // Each payload is sized to the capacity of its version and level: v1-L holds
    // 17 bytes, v2-M 26, v7-Q 86 and v12-H 155. A share link is nowhere near
    // these limits, but the sizes are spread out so the walk is exercised across
    // single and multiple block layouts.
    for (const [text, version, ecc] of [
      ['hello world', 1, 'L'],
      ['https://a.example/s/ab#c', 2, 'M'],
      ['x'.repeat(86), 7, 'Q'],
      ['y'.repeat(155), 12, 'H'],
    ] as const) {
      const oracle = oracleSymbol(text, version, ecc);
      const decoded = decodeSymbol(oracle.modules, oracle.size);
      expect(decoded.text).toBe(text);
      expect(decoded.version).toBe(version);
      expect(decoded.ecc).toBe(ecc);
    }
  });
});

describe('encodeQr', () => {
  it('round-trips a share link at every error correction level', () => {
    const link = 'https://secrets.example/s/9Xk2mQpLr7Tn#wZ4bXc8dEv1KmNhJ6y';
    for (const ecc of ['L', 'M', 'Q', 'H'] as const) {
      const symbol = encodeQr(link, ecc);
      const decoded = decodeSymbol(symbol.modules, symbol.size);
      expect(decoded.text).toBe(link);
      expect(decoded.ecc).toBe(ecc);
      expect(decoded.version).toBe(symbol.version);
      expect(decoded.mask).toBe(symbol.mask);
    }
  });

  it('picks a symbol that fits the payload', () => {
    // Capacity is the data codewords of the version less the mode and length
    // header: version 1 at level M holds 16 codewords, so 14 bytes, and the
    // seventeenth byte already needs version 2.
    expect(encodeQr('a').version).toBe(1);
    expect(encodeQr('a'.repeat(14), 'M').version).toBe(1);
    expect(encodeQr('a'.repeat(15), 'M').version).toBe(2);
    expect(encodeQr('a'.repeat(120)).version).toBeGreaterThan(4);
  });

  it('reports a payload that no version can hold', () => {
    expect(() => encodeQr('a'.repeat(3000), 'H')).toThrow(QrCapacityError);
    try {
      encodeQr('a'.repeat(3000), 'H');
      expect.unreachable('expected a capacity error');
    } catch (error) {
      expect(error).toBeInstanceOf(QrCapacityError);
      expect((error as QrCapacityError).requiredBytes).toBe(3000);
      expect((error as QrCapacityError).capacityBytes).toBeGreaterThan(0);
    }
  });

  it('reports the capacity of the largest symbol', () => {
    const error = (() => {
      try {
        encodeQr('a'.repeat(4000), 'L');
        return null;
      } catch (thrown) {
        return thrown as QrCapacityError;
      }
    })();
    // Version 40 at level L carries 2956 data codewords; a sixteen bit length
    // indicator and the four mode bits cost three of those bytes.
    expect(error?.capacityBytes).toBe(2953);
  });

  it('encodes UTF-8 beyond ASCII', () => {
    const text = 'segreto àèìòù 密码 🔐';
    const symbol = encodeQr(text);
    const decoded = decodeSymbol(symbol.modules, symbol.size);
    expect(decoded.text).toBe(text);
  });

  it('encodes every boundary length of a version without drifting', () => {
    // Lengths either side of every capacity boundary catch an off-by-one in the
    // terminator, the padding or the character count indicator.
    for (let length = 1; length <= 60; length += 1) {
      const text = 'z'.repeat(length);
      const symbol = encodeQr(text, 'M');
      expect(decodeSymbol(symbol.modules, symbol.size).text).toBe(text);
    }
  });

  it('handles a payload that exactly fills its version', () => {
    // Version 4 at level M carries two blocks of 32 data codewords, which is 62
    // bytes: filling it exactly leaves no room for a terminator or any pad
    // codeword.
    const filled = 'q'.repeat(62);
    const symbol = encodeQr(filled, 'M');
    expect(symbol.version).toBe(4);
    expect(decodeSymbol(symbol.modules, symbol.size).text).toBe(filled);
  });

  it('keeps the same symbol for the same input', () => {
    const text = 'https://secrets.example/s/deterministic#key';
    const first = encodeQr(text);
    const second = encodeQr(text);
    expect(second.mask).toBe(first.mask);
    expect(second.modules).toEqual(first.modules);
  });
});

describe('block table arithmetic', () => {
  /**
   * The decoder's own copy of the table is what every decode above relies on, so
   * it is checked against the two published facts that constrain it: the total
   * codeword count of a version, and the number of modules a symbol leaves over
   * once its function patterns are placed. A transcription slip in either table
   * shows up here rather than as a mysterious decode failure.
   */
  it('reproduces the total codewords and the free module count of every version', () => {
    for (let version = 1; version <= 40; version += 1) {
      const size = version * 4 + 17;
      const reserved = reservedModules(size, version);
      let free = 0;
      for (const line of reserved) for (const value of line) if (!value) free += 1;

      const expectedBits = (TOTAL_CODEWORDS[version] as number) * 8 + (REMAINDER_BITS[version - 1] as number);
      expect(free, `version ${version} free modules`).toBe(expectedBits);

      for (const ecc of ['L', 'M', 'Q', 'H'] as const) {
        const entry = (RS_BLOCK_TABLE[version - 1] as readonly (readonly number[])[])[ECC_ORDER[ecc]] as readonly number[];
        const ecPerBlock = entry[0] as number;
        let blocks = 0;
        let codewords = 0;
        for (let index = 1; index < entry.length; index += 2) {
          const count = entry[index] as number;
          const data = entry[index + 1] as number;
          blocks += count;
          codewords += count * (data + ecPerBlock);
        }
        expect(codewords, `version ${version} level ${ecc} codewords`).toBe(TOTAL_CODEWORDS[version]);
        expect(blocks, `version ${version} level ${ecc} blocks`).toBeGreaterThan(0);
      }
    }
  });
});

describe('agreement with the reference encoder', () => {
  /**
   * The decoded payload proves a symbol is self-consistent; it does not prove it
   * matches what other readers expect. This sweep closes that gap: for every
   * level and a spread of versions, both encoders are asked for the same text
   * and the resulting codewords are compared. The mask is allowed to differ,
   * because the reference uses a non-standard penalty function, so the
   * comparison is made on the unmasked codeword stream.
   */
  it('produces the same codewords as the reference encoder', () => {
    const levels: readonly Ecc[] = ['L', 'M', 'Q', 'H'];
    // A share link is the realistic input; these lengths also cross the
    // single-block to multi-block boundary at several versions.
    const texts = [
      'https://secrets.example/s/9Xk2mQpLr7Tn#wZ4bXc8dEv1KmNhJ6y',
      'a'.repeat(40),
      'a'.repeat(120),
      'a'.repeat(300),
    ];
    let compared = 0;
    for (const ecc of levels) {
      for (const text of texts) {
        const mine = encodeQr(text, ecc);
        const reference = oracleSymbol(text, mine.version, ecc);
        // Decode both: this yields the level and mask the reader would infer,
        // and re-derives the codeword stream with the mask removed.
        const decodedMine = decodeSymbol(mine.modules, mine.size);
        const decodedReference = decodeSymbol(reference.modules, reference.size);
        expect(decodedMine.text).toBe(text);
        expect(decodedReference.text).toBe(text);
        expect(decodedMine.ecc).toBe(ecc);
        expect(decodedReference.ecc).toBe(ecc);
        expect(decodedMine.version).toBe(mine.version);
        expect(decodedReference.version).toBe(mine.version);
        // Same payload, same version, same level and same codewords: the only
        // thing left free is which mask was picked, and that is a scoring choice.
        expect(codewordsOf(mine.modules, mine.size)).toEqual(codewordsOf(reference.modules, reference.size));
        compared += 1;
      }
    }
    expect(compared).toBe(levels.length * texts.length);
  });

  it('chooses a mask the reference decoder can read back', () => {
    // The mask is the one part that is allowed to differ, so it gets its own
    // check: whatever this encoder picks, the format information has to say so.
    for (const text of ['a', 'a'.repeat(60), 'a'.repeat(200), 'a'.repeat(700)]) {
      for (const ecc of ['L', 'M', 'Q', 'H'] as const) {
        const symbol = encodeQr(text, ecc);
        expect(symbol.mask).toBeGreaterThanOrEqual(0);
        expect(symbol.mask).toBeLessThan(8);
        // Reading the format information back must reproduce the mask recorded
        // on the symbol, which is what a scanner uses to unmask.
        expect(decodeSymbol(symbol.modules, symbol.size).mask).toBe(symbol.mask);
      }
    }
  });
});

/** The unmasked codeword stream a scanner would read out of a symbol. */
function codewordsOf(modules: readonly (readonly boolean[])[], size: number): number[] {
  let format = 0;
  const bit = (index: number): boolean => {
    if (index < 6) return at(modules, index, 8);
    if (index === 6) return at(modules, 7, 8);
    if (index === 7) return at(modules, 8, 8);
    if (index === 8) return at(modules, 8, 7);
    return at(modules, 8, 14 - index);
  };
  for (let index = 0; index < 15; index += 1) if (bit(index)) format |= 1 << index;
  const mask = ((format ^ 0b101010000010010) >>> 10) & 0b111;
  const stream = unmaskedStream(modules, size, mask);
  const codewords: number[] = [];
  for (let index = 0; index + 8 <= stream.length; index += 8) {
    let byte = 0;
    for (let offset = 0; offset < 8; offset += 1) byte = (byte << 1) | (stream[index + offset] as number);
    codewords.push(byte);
  }
  return codewords;
}

describe('symbol layout', () => {
  const symbol = encodeQr('https://secrets.example/s/layout#check');

  it('places the three finder patterns', () => {
    const finder = (top: number, left: number): boolean[] =>
      Array.from({ length: 7 }, (_, row) =>
        Array.from({ length: 7 }, (_, column) => {
          const edge = row === 0 || row === 6 || column === 0 || column === 6;
          const core = row >= 2 && row <= 4 && column >= 2 && column <= 4;
          return symbol.isDark(top + row, left + column) === (edge || core);
        }),
      ).flatMap((row) => row);

    const size = symbol.size;
    const rings = [
      ...finder(0, 0),
      ...finder(0, size - 7),
      ...finder(size - 7, 0),
    ];
    expect(rings.every((dark) => dark)).toBe(true);
  });

  it('leaves a light separator around the finder patterns', () => {
    const size = symbol.size;
    expect(symbol.isDark(7, 0)).toBe(false);
    expect(symbol.isDark(7, 7)).toBe(false);
    expect(symbol.isDark(0, 7)).toBe(false);
    expect(symbol.isDark(7, size - 8)).toBe(false);
    expect(symbol.isDark(size - 8, 7)).toBe(false);
  });

  it('alternates along the timing patterns', () => {
    for (let index = 8; index < symbol.size - 8; index += 1) {
      expect(symbol.isDark(6, index)).toBe(index % 2 === 0);
      expect(symbol.isDark(index, 6)).toBe(index % 2 === 0);
    }
  });

  it('keeps the fixed dark module', () => {
    expect(symbol.isDark(symbol.size - 8, 8)).toBe(true);
  });

  it('sizes the symbol from the version', () => {
    expect(symbol.size).toBe(symbol.version * 4 + 17);
    expect(symbol.modules.length).toBe(symbol.size);
    for (const row of symbol.modules) expect(row.length).toBe(symbol.size);
  });

  it('writes version information from version 7 upwards', () => {
    const seen = new Set<number>();
    // Walk the whole range: the BCH remainder is what catches a division that
    // starts at the wrong bit, and that only shows up above version 7.
    for (let length = 1; length <= 1200 && seen.size < 20; length += 1) {
      const large = encodeQr('v'.repeat(length), 'M');
      if (large.version < 7 || seen.has(large.version)) continue;
      seen.add(large.version);
      const size = large.size;
      // Both copies must agree, which only holds if the block was placed twice.
      let first = 0;
      let second = 0;
      for (let index = 0; index < 18; index += 1) {
        const row = Math.floor(index / 3);
        const column = size - 11 + (index % 3);
        if (large.isDark(row, column)) first |= 1 << index;
        if (large.isDark(column, row)) second |= 1 << index;
      }
      expect(first).toBe(second);
      expect(first >>> 12).toBe(large.version);
      // The lower twelve bits are the BCH remainder, and a scanner validates
      // them exactly like this before trusting the version.
      let remainder = first;
      for (let bit = 17; bit >= 12; bit -= 1) {
        if ((remainder >>> bit) & 1) remainder ^= 0b1111100100101 << (bit - 12);
      }
      expect(remainder & 0xfff).toBe(0);
    }
    expect(seen.size).toBeGreaterThanOrEqual(20);
  });
});

describe('svg rendering', () => {
  it('emits a square document with a light quiet zone', () => {
    const symbol = encodeQr('https://secrets.example/s/svg#check');
    const svg = qrToSvg(symbol, { title: 'QR' });
    const extent = symbol.size + 8;
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).toContain(`viewBox="0 0 ${extent} ${extent}"`);
    expect(svg).toContain(`width="${extent}" height="${extent}"`);
    expect(svg).toContain('fill="#ffffff"');
    expect(svg).toContain('<title>QR</title>');
    expect(svg).toContain('role="img"');
  });

  it('escapes a title rather than injecting markup', () => {
    const svg = qrToSvg(encodeQr('x'), { title: '<script>alert(1)</script> & "co"' });
    expect(svg).not.toContain('<script>');
    expect(svg).toContain('&lt;script&gt;');
    expect(svg).toContain('&amp;');
  });

  it('runs modules into contiguous horizontal segments', () => {
    const symbol = encodeQr('https://secrets.example/s/path#check');
    const path = qrToSvgPath(symbol, 4);
    // Each command is one dark run drawn as a filled rectangle, and the quiet
    // zone offset must appear so the code is not flush against the edge.
    expect(path).toMatch(/^M4 4h\d+v1h-\d+z/);
    expect(path).not.toContain('NaN');
    expect(path).not.toContain('undefined');
    // Every dark module must be covered by exactly one command.
    const covered = new Set<string>();
    for (const match of path.matchAll(/M(\d+) (\d+)h(\d+)/g)) {
      const [, x, y, width] = match;
      for (let step = 0; step < Number(width); step += 1) covered.add(`${Number(y) - 4},${Number(x) + step - 4}`);
    }
    const dark: string[] = [];
    symbol.modules.forEach((row, rowIndex) =>
      row.forEach((value, columnIndex) => {
        if (value) dark.push(`${rowIndex},${columnIndex}`);
      }),
    );
    expect([...covered].sort()).toEqual(dark.sort());
  });

  it('covers every dark module of a multi-block symbol', () => {
    for (const length of [10, 80, 300]) {
      const symbol = encodeQr('w'.repeat(length));
      const path = qrToSvgPath(symbol);
      const covered = new Set<string>();
      for (const match of path.matchAll(/M(\d+) (\d+)h(\d+)/g)) {
        const [, x, y, width] = match;
        for (let step = 0; step < Number(width); step += 1) covered.add(`${Number(y) - 4},${Number(x) + step - 4}`);
      }
      const dark = new Set<string>();
      symbol.modules.forEach((row, rowIndex) =>
        row.forEach((value, columnIndex) => {
          if (value) dark.add(`${rowIndex},${columnIndex}`);
        }),
      );
      expect(covered).toEqual(dark);
    }
  });
});
