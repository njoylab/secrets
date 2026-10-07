/**
 * QR Code encoder, byte mode only.
 *
 * Scope is deliberately narrow: the only thing this has to encode is a share
 * link, which is short, ASCII and never needs anything but byte mode. That
 * leaves out kanji mode, ECI, structured append and the Micro QR variants,
 * which is what keeps this file readable and auditable.
 *
 * Implemented from ISO/IEC 18004: mode and version selection, bit packing with
 * the 0xEC/0x11 terminator, Reed-Solomon over GF(256) with the 0x11D
 * primitive polynomial, block interleaving, function pattern layout, the eight
 * data masks with the four penalty rules, and the BCH format and version
 * information.
 *
 * The matrix this returns is validated in `tests/qr.test.ts` by decoding it
 * back, so a silent mistake here shows up as a failing test rather than as a
 * code no scanner can read.
 */

/** Error correction level. `M` is the default: enough redundancy to survive a
 * screen photographed at an angle, without inflating a short link. */
export type QrEccLevel = 'L' | 'M' | 'Q' | 'H';

/** Two bits per level, as they appear in the format information. */
const ECC_FORMAT_BITS: Readonly<Record<QrEccLevel, number>> = Object.freeze({
  L: 0b01,
  M: 0b00,
  Q: 0b11,
  H: 0b10,
});

const MIN_VERSION = 1;
const MAX_VERSION = 40;

/**
 * Block layout per version and error correction level, ordered L, M, Q, H.
 *
 * Each entry is `[ecCodewordsPerBlock, ...groups]`, where a group is a pair of
 * `blockCount, dataCodewordsPerBlock`. The table is the published one, checked
 * against the total codeword counts of every version by `tests/qr.test.ts`.
 */
const RS_BLOCK_TABLE = Object.freeze([
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
] as const);

/** Centre coordinates of the alignment patterns, indexed by version minus one. */
const ALIGNMENT_PATTERN_POSITIONS: Readonly<readonly (readonly number[])[]> = Object.freeze([
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
  [6, 30, 54],
  [6, 32, 58],
  [6, 34, 62],
  [6, 26, 46, 66],
  [6, 26, 48, 70],
  [6, 26, 50, 74],
  [6, 30, 54, 78],
  [6, 30, 56, 82],
  [6, 30, 58, 86],
  [6, 34, 62, 90],
  [6, 28, 50, 72, 94],
  [6, 26, 50, 74, 98],
  [6, 30, 54, 78, 102],
  [6, 28, 54, 80, 106],
  [6, 32, 58, 84, 110],
  [6, 30, 58, 86, 114],
  [6, 34, 62, 90, 118],
  [6, 26, 50, 74, 98, 122],
  [6, 30, 54, 78, 102, 126],
  [6, 26, 52, 78, 104, 130],
  [6, 30, 56, 82, 108, 134],
  [6, 34, 60, 86, 112, 138],
  [6, 30, 58, 86, 114, 142],
  [6, 34, 62, 90, 118, 146],
  [6, 30, 54, 78, 102, 126, 150],
  [6, 24, 50, 76, 102, 128, 154],
  [6, 28, 54, 80, 106, 132, 158],
  [6, 32, 58, 84, 110, 136, 162],
  [6, 26, 54, 82, 110, 138, 166],
  [6, 30, 58, 86, 114, 142, 170],
] as const);

/**
 * Unused modules left over after the codewords, per version.
 *
 * They stay light and are still masked, which is why the data placement has to
 * run over the whole symbol rather than over the codeword length alone.
 */
const REMAINDER_BITS: Readonly<readonly number[]> = Object.freeze([
  0, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3,
  4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0,
] as const);

export class QrCapacityError extends Error {
  constructor(
    readonly requiredBytes: number,
    readonly capacityBytes: number,
  ) {
    super(`QR payload needs ${requiredBytes} bytes, the largest symbol holds ${capacityBytes}`);
    this.name = 'QrCapacityError';
  }
}

/** An encoded symbol: one dark/light bit per module, plus what produced it. */
export interface QrSymbol {
  readonly version: number;
  readonly size: number;
  readonly ecc: QrEccLevel;
  readonly mask: number;
  /** `modules[row][col]` is true for a dark module. */
  readonly modules: ModuleGrid;
  /**
   * Whether the module at a position is dark.
   *
   * Preferred over subscripting `modules` directly: the grid is square, so an
   * index out of range is a caller bug rather than a light module, and this
   * keeps that visible under `noUncheckedIndexedAccess`.
   */
  isDark(row: number, column: number): boolean;
}

/** GF(256) exponent table, built once because every block needs it. */
const GF_EXP = new Uint8Array(512);
/** Logarithms, so multiplication reduces to a table lookup. */
const GF_LOG = new Uint8Array(256);

(function buildGaloisField(): void {
  let value = 1;
  for (let power = 0; power < 255; power += 1) {
    GF_EXP[power] = value;
    GF_LOG[value] = power;
    // Multiply by the generator 2, reducing by the primitive polynomial x^8+x^4+x^3+x^2+1.
    value <<= 1;
    if (value & 0x100) value ^= 0x11d;
  }
  // The second half lets the encoder index sums of two exponents without wrapping.
  for (let power = 255; power < 512; power += 1) {
    GF_EXP[power] = GF_EXP[power - 255] as number;
  }
})();

function gfMultiply(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[(GF_LOG[a] as number) + (GF_LOG[b] as number)] as number;
}

/**
 * Reed-Solomon generator polynomial of the given degree.
 *
 * Stored without its leading coefficient, which is always 1, because that
 * coefficient is only ever implicit in the remainder computation below.
 */
function generatorPolynomial(degree: number): Uint8Array {
  const polynomial = new Uint8Array(degree);
  polynomial[degree - 1] = 1;
  let root = 1;
  for (let step = 0; step < degree; step += 1) {
    for (let index = 0; index < degree; index += 1) {
      polynomial[index] = gfMultiply(polynomial[index] as number, root);
      if (index + 1 < degree) {
        polynomial[index] = (polynomial[index] as number) ^ (polynomial[index + 1] as number);
      }
    }
    root = gfMultiply(root, 2);
  }
  return polynomial;
}

const GENERATOR_CACHE = new Map<number, Uint8Array>();

function cachedGenerator(degree: number): Uint8Array {
  const cached = GENERATOR_CACHE.get(degree);
  if (cached) return cached;
  const polynomial = generatorPolynomial(degree);
  GENERATOR_CACHE.set(degree, polynomial);
  return polynomial;
}

/**
 * Error correction codewords for one block.
 *
 * This is the standard remainder of `data * x^degree` divided by the generator
 * polynomial, carried out over GF(256).
 */
function reedSolomonEncode(data: Uint8Array, degree: number): Uint8Array {
  const generator = cachedGenerator(degree);
  const remainder = new Uint8Array(degree);
  for (const value of data) {
    const factor = value ^ (remainder[0] as number);
    remainder.copyWithin(0, 1);
    remainder[degree - 1] = 0;
    if (factor !== 0) {
      for (let index = 0; index < degree; index += 1) {
        remainder[index] = (remainder[index] as number) ^ gfMultiply(generator[index] as number, factor);
      }
    }
  }
  return remainder;
}

interface BlockLayout {
  readonly total: number;
  readonly data: number;
  readonly ec: number;
}

/** Column of each level in the block table. */
const ECC_ORDER: Readonly<Record<QrEccLevel, number>> = Object.freeze({ L: 0, M: 1, Q: 2, H: 3 });

/** Decode the flat table entry for a version and level into block sizes. */
function blockLayout(version: number, ecc: QrEccLevel): readonly BlockLayout[] {
  const entry = RS_BLOCK_TABLE[version - 1]?.[ECC_ORDER[ecc]] as readonly number[] | undefined;
  if (!entry) throw new Error(`No block layout for version ${version} at level ${ecc}`);
  const ec = entry[0] as number;
  const layout: BlockLayout[] = [];
  // After the EC count the entry is a flat run of blockCount/dataCount pairs.
  for (let index = 1; index < entry.length; index += 2) {
    const blocks = entry[index] as number;
    const data = entry[index + 1] as number;
    for (let count = 0; count < blocks; count += 1) {
      layout.push({ total: data + ec, data, ec });
    }
  }
  return layout;
}

/** Data codewords a version and level can carry, before the mode header. */
function dataCodewordCount(version: number, ecc: QrEccLevel): number {
  return blockLayout(version, ecc).reduce((sum, block) => sum + block.data, 0);
}

/** Bits in the character count indicator for byte mode. */
function characterCountBits(version: number): number {
  return version <= 9 ? 8 : 16;
}

/** Largest payload this symbol can carry, in bytes of UTF-8. */
function capacityBytes(version: number, ecc: QrEccLevel): number {
  const headerBits = 4 + characterCountBits(version);
  return Math.floor((dataCodewordCount(version, ecc) * 8 - headerBits) / 8);
}

/** The smallest version that fits the payload, or null when none does. */
function selectVersion(byteLength: number, ecc: QrEccLevel): number | null {
  for (let version = MIN_VERSION; version <= MAX_VERSION; version += 1) {
    if (byteLength <= capacityBytes(version, ecc)) return version;
  }
  return null;
}

/**
 * Mode header, length and payload, then the terminator and the pad codewords.
 *
 * The bit string is written most significant bit first and padded to a whole
 * number of codewords, alternating 0xEC and 0x11 as the standard requires.
 */
function buildDataCodewords(bytes: Uint8Array, version: number, ecc: QrEccLevel): Uint8Array {
  const totalData = dataCodewordCount(version, ecc);
  const bits: number[] = [];

  const push = (value: number, length: number): void => {
    for (let shift = length - 1; shift >= 0; shift -= 1) {
      bits.push((value >>> shift) & 1);
    }
  };

  push(0b0100, 4);
  push(bytes.length, characterCountBits(version));
  for (const value of bytes) push(value, 8);

  const capacityBits = totalData * 8;
  // Up to four zero bits of terminator, and only if the symbol is not already full.
  for (let index = 0; index < 4 && bits.length < capacityBits; index += 1) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);

  const codewords = new Uint8Array(totalData);
  for (let index = 0; index < bits.length; index += 8) {
    let byte = 0;
    for (let offset = 0; offset < 8; offset += 1) byte = (byte << 1) | (bits[index + offset] as number);
    codewords[index / 8] = byte;
  }
  // The alternation starts at the first free codeword, not at an absolute
  // position: whether that position is even or odd depends on the payload
  // length, and the pattern itself does not.
  const firstPad = bits.length / 8;
  for (let index = firstPad; index < totalData; index += 1) {
    codewords[index] = (index - firstPad) % 2 === 0 ? 0xec : 0x11;
  }
  return codewords;
}

/**
 * Split into blocks, append the error correction and interleave both halves.
 *
 * Interleaving is what lets a partial scan survive: the codewords of every block
 * are spread across the symbol, so damage hits all blocks a little instead of
 * destroying one entirely.
 */
function interleave(codewords: Uint8Array, version: number, ecc: QrEccLevel): Uint8Array {
  const layout = blockLayout(version, ecc);
  const dataBlocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];
  let offset = 0;
  for (const block of layout) {
    const data = codewords.subarray(offset, offset + block.data);
    offset += block.data;
    dataBlocks.push(data);
    ecBlocks.push(reedSolomonEncode(data, block.ec));
  }

  const total = layout.reduce((sum, block) => sum + block.total, 0);
  const output = new Uint8Array(total);
  let position = 0;
  const longestData = Math.max(...dataBlocks.map((block) => block.length));
  const ecPerBlock = layout[0]?.ec ?? 0;
  // Data first: blocks shorter than the longest simply stop contributing.
  for (let index = 0; index < longestData; index += 1) {
    for (const block of dataBlocks) {
      if (index < block.length) output[position++] = block[index] as number;
    }
  }
  // Every block contributes the same number of EC codewords, so no bound here.
  for (let index = 0; index < ecPerBlock; index += 1) {
    for (const block of ecBlocks) {
      output[position++] = block[index] as number;
    }
  }
  return output;
}

/** BCH(15,5) format information, masked so an all-zero pattern is not a valid code. */
function formatInformation(ecc: QrEccLevel, mask: number): number {
  const data = (ECC_FORMAT_BITS[ecc] << 3) | mask;
  return ((data << 10) | bchRemainder(data << 10, 0b10100110111, 10)) ^ 0b101010000010010;
}

/** BCH(18,6) version information, used from version 7 upwards. */
function versionInformation(version: number): number {
  return (version << 12) | bchRemainder(version << 12, 0b1111100100101, 12);
}

/**
 * Remainder of `value` divided by the BCH generator polynomial.
 *
 * Long division, from the highest bit down. `degree` is the index of the
 * generator's top bit, so the result carries no bit at or above it.
 */
function bchRemainder(value: number, generator: number, degree: number): number {
  let remainder = value;
  // The loop starts at the highest set bit of the value, not at a fixed
  // position: the format block is fifteen bits wide and the version block
  // eighteen, and starting too low would skip the top of the division.
  for (let bit = 31 - Math.clz32(value); bit >= degree; bit -= 1) {
    if (((remainder >>> bit) & 1) === 1) remainder ^= generator << (bit - degree);
  }
  return remainder & ((1 << degree) - 1);
}

/**
 * A grid of modules, one boolean each: true is dark.
 *
 * Reads go through `moduleAt` rather than subscripting directly. The grid is
 * square by construction and every index has already been range checked by the
 * caller, so a missing entry can only be a bug, and treating it as light keeps
 * that bug from turning into a silently wrong symbol.
 */
type ModuleGrid = readonly (readonly boolean[])[];

function moduleAt(modules: ModuleGrid, row: number, column: number): boolean {
  return modules[row]?.[column] ?? false;
}

function setModule(modules: boolean[][], row: number, column: number, dark: boolean): void {
  const line = modules[row];
  if (line) line[column] = dark;
}

/**
 * Whether the mask flips a module.
 *
 * `row` and `column` are taken as given, not swapped: the spec defines the
 * patterns in terms of the module's row and column, and every reader agrees on
 * that convention.
 */
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

/**
 * Place the function patterns and mark every module they own.
 *
 * The `reserved` grid is what keeps the data walk out of the finder patterns,
 * the timing lines, the format and version areas and the alignment patterns. A
 * module listed here is never data and never masked.
 */
function layoutFunctionPatterns(
  size: number,
  version: number,
  reserved: boolean[][],
  set: (row: number, column: number, dark: boolean) => void,
): void {
  const reserve = (row: number, column: number): void => {
    setModule(reserved, row, column, true);
  };

  const finder = (topRow: number, leftColumn: number): void => {
    for (let row = -1; row <= 7; row += 1) {
      for (let column = -1; column <= 7; column += 1) {
        const targetRow = topRow + row;
        const targetColumn = leftColumn + column;
        if (targetRow < 0 || targetRow >= size || targetColumn < 0 || targetColumn >= size) continue;
        reserve(targetRow, targetColumn);
        // The 7x7 ring, the 3x3 core, and the separator ring around both.
        const inRing =
          row >= 0 && row <= 6 && column >= 0 && column <= 6 &&
          (row === 0 || row === 6 || column === 0 || column === 6 ||
            (row >= 2 && row <= 4 && column >= 2 && column <= 4));
        set(targetRow, targetColumn, inRing);
      }
    }
  };

  finder(0, 0);
  finder(0, size - 7);
  finder(size - 7, 0);

  // Timing patterns: alternating light and dark from the eighth module onwards.
  for (let index = 8; index < size - 8; index += 1) {
    const dark = index % 2 === 0;
    reserve(6, index);
    set(6, index, dark);
    reserve(index, 6);
    set(index, 6, dark);
  }

  // Alignment patterns, skipping the three corners the finder patterns own.
  const positions = ALIGNMENT_PATTERN_POSITIONS[version - 1] ?? [];
  for (const row of positions) {
    for (const column of positions) {
      const nearFinder =
        (row === 6 && column === 6) ||
        (row === 6 && column === size - 7) ||
        (row === size - 7 && column === 6);
      if (nearFinder) continue;
      for (let deltaRow = -2; deltaRow <= 2; deltaRow += 1) {
        for (let deltaColumn = -2; deltaColumn <= 2; deltaColumn += 1) {
          const targetRow = row + deltaRow;
          const targetColumn = column + deltaColumn;
          reserve(targetRow, targetColumn);
          const edge = Math.abs(deltaRow) === 2 || Math.abs(deltaColumn) === 2;
          const core = deltaRow === 0 && deltaColumn === 0;
          set(targetRow, targetColumn, edge || core);
        }
      }
    }
  }

  // The always-dark module below the top-left format information.
  reserve(size - 8, 8);
  set(size - 8, 8, true);

  // Reserve the format information in both copies without deciding its value:
  // it depends on the mask, which is only chosen after the data is placed.
  for (let index = 0; index <= 8; index += 1) {
    if (index !== 6) {
      reserve(8, index);
      reserve(index, 8);
    }
  }
  for (let index = 0; index < 8; index += 1) {
    reserve(8, size - 1 - index);
    reserve(size - 1 - index, 8);
  }

  if (version >= 7) {
    for (let index = 0; index < 18; index += 1) {
      const row = Math.floor(index / 3);
      const column = size - 11 + (index % 3);
      reserve(row, column);
      reserve(column, row);
    }
  }
}

/** Write one copy of the format information and both copies of the version block. */
function writeMetadata(
  modules: boolean[][],
  version: number,
  ecc: QrEccLevel,
  mask: number,
): void {
  const size = modules.length;
  const format = formatInformation(ecc, mask);
  for (let index = 0; index < 15; index += 1) {
    const dark = ((format >>> index) & 1) === 1;
    // Copy one: around the top-left finder pattern, read from bit 14 downwards.
    if (index < 6) setModule(modules, index, 8, dark);
    else if (index === 6) setModule(modules, 7, 8, dark);
    else if (index === 7) setModule(modules, 8, 8, dark);
    else if (index === 8) setModule(modules, 8, 7, dark);
    else setModule(modules, 8, 14 - index, dark);
    // Copy two: split between the other two finder patterns.
    if (index < 8) setModule(modules, 8, size - 1 - index, dark);
    else setModule(modules, size - 15 + index, 8, dark);
  }

  if (version >= 7) {
    const versionBits = versionInformation(version);
    for (let index = 0; index < 18; index += 1) {
      const dark = ((versionBits >>> index) & 1) === 1;
      const row = Math.floor(index / 3);
      const column = size - 11 + (index % 3);
      setModule(modules, row, column, dark);
      setModule(modules, column, row, dark);
    }
  }
}

/**
 * Walk the data area two columns at a time, bottom right to top left.
 *
 * The zigzag alternates direction every two columns so that a symbol survives
 * damage along a scan line. Column 6 is skipped because the vertical timing
 * pattern runs through it.
 */
function placeData(modules: boolean[][], reserved: boolean[][], codewords: Uint8Array): void {
  const size = modules.length;
  let bitIndex = 0;
  let upward = true;

  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step += 1) {
      const row = upward ? size - 1 - step : step;
      for (let offset = 0; offset < 2; offset += 1) {
        const column = right - offset;
        if (moduleAt(reserved, row, column)) continue;
        // Past the codewords only the remainder bits are left: they stay light.
        const dark = bitIndex < codewords.length * 8
          ? (((codewords[bitIndex >>> 3] ?? 0) >>> (7 - (bitIndex & 7))) & 1) === 1
          : false;
        setModule(modules, row, column, dark);
        bitIndex += 1;
      }
    }
    upward = !upward;
  }
}

/** Apply a mask to the data area only. */
function applyMask(modules: boolean[][], reserved: boolean[][], mask: number): void {
  for (let row = 0; row < modules.length; row += 1) {
    for (let column = 0; column < modules.length; column += 1) {
      if (moduleAt(reserved, row, column)) continue;
      if (maskApplies(mask, row, column)) setModule(modules, row, column, !moduleAt(modules, row, column));
    }
  }
}

/**
 * Penalty score for a symbol, the four rules of the standard.
 *
 * Lower is better. The counts are the published ones so that the mask choice
 * matches what other encoders produce, which keeps symbols comparable and makes
 * this function straightforward to check against a reference.
 */
function penalty(modules: ModuleGrid): number {
  const size = modules.length;
  let score = 0;

  // Rule 1: five or more modules of one colour in a row or a column.
  for (let row = 0; row < size; row += 1) {
    for (const horizontal of [true, false]) {
      let run = 1;
      for (let index = 1; index < size; index += 1) {
        const current = horizontal ? moduleAt(modules, row, index) : moduleAt(modules, index, row);
        const previous = horizontal ? moduleAt(modules, row, index - 1) : moduleAt(modules, index - 1, row);
        if (current === previous) {
          run += 1;
        } else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
      }
      if (run >= 5) score += 3 + (run - 5);
    }
  }

  // Rule 2: every 2x2 block of one colour.
  for (let row = 0; row < size - 1; row += 1) {
    for (let column = 0; column < size - 1; column += 1) {
      const value = moduleAt(modules, row, column);
      if (
        value === moduleAt(modules, row, column + 1) &&
        value === moduleAt(modules, row + 1, column) &&
        value === moduleAt(modules, row + 1, column + 1)
      ) {
        score += 3;
      }
    }
  }

  // Rule 3: a 1:1:3:1:1 run with four light modules beside it, which a scanner
  // can mistake for a finder pattern.
  const pattern = [true, false, true, true, true, false, true];
  const matchesAt = (get: (index: number) => boolean, start: number): boolean => {
    for (let index = 0; index < 7; index += 1) {
      if (get(start + index) !== pattern[index]) return false;
    }
    const before = [start - 4, start - 3, start - 2, start - 1].every((index) => index >= 0 && !get(index));
    const after = [start + 7, start + 8, start + 9, start + 10].every(
      (index) => index < size && !get(index),
    );
    return before || after;
  };
  for (let row = 0; row < size; row += 1) {
    for (let column = 0; column <= size - 7; column += 1) {
      if (matchesAt((index) => moduleAt(modules, row, index), column)) score += 40;
    }
  }
  for (let column = 0; column < size; column += 1) {
    for (let row = 0; row <= size - 7; row += 1) {
      if (matchesAt((index) => moduleAt(modules, index, column), row)) score += 40;
    }
  }

  // Rule 4: how far the proportion of dark modules sits from one half.
  let dark = 0;
  for (const row of modules) {
    for (const value of row) if (value) dark += 1;
  }
  const percent = (100 * dark) / (size * size);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return score;
}

/**
 * Encode text as a QR symbol in byte mode.
 *
 * @throws {QrCapacityError} when the text does not fit in any version, which for
 * this application means a share link far longer than any real one.
 */
export function encodeQr(text: string, ecc: QrEccLevel = 'M'): QrSymbol {
  const bytes = new TextEncoder().encode(text);
  const version = selectVersion(bytes.length, ecc);
  if (version === null) {
    throw new QrCapacityError(bytes.length, capacityBytes(MAX_VERSION, ecc));
  }

  const size = version * 4 + 17;
  const modules: boolean[][] = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const reserved: boolean[][] = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const set = (row: number, column: number, dark: boolean): void => {
    setModule(modules, row, column, dark);
  };

  layoutFunctionPatterns(size, version, reserved, set);

  const codewords = interleave(buildDataCodewords(bytes, version, ecc), version, ecc);

  // Try all eight masks and keep the least penalised symbol. The winning
  // candidate is kept as well as its score: the base grid never receives the
  // data, so the symbol has to be the one that was actually built.
  let best: { readonly score: number; readonly mask: number; readonly grid: boolean[][] } | null = null;
  for (let mask = 0; mask < 8; mask += 1) {
    const candidate: boolean[][] = modules.map((row) => [...row]);
    placeData(candidate, reserved, codewords);
    applyMask(candidate, reserved, mask);
    writeMetadata(candidate, version, ecc, mask);
    const score = penalty(candidate);
    if (!best || score < best.score) best = { score, mask, grid: candidate };
  }

  if (!best) throw new Error('No mask was evaluated');
  const grid = best.grid;
  return {
    version,
    size,
    ecc,
    mask: best.mask,
    modules: grid,
    isDark: (row, column) => moduleAt(grid, row, column),
  };
}

/**
 * The symbol as an SVG path, one `M h v h z` per run of dark modules.
 *
 * Emitting runs rather than squares keeps the markup small: a version 4 symbol
 * is a few hundred bytes instead of a few kilobytes. A quiet zone of four
 * modules is required by the standard and included here.
 */
export function qrToSvgPath(symbol: QrSymbol, quietZone = 4): string {
  const commands: string[] = [];
  for (let row = 0; row < symbol.size; row += 1) {
    let runStart = -1;
    for (let column = 0; column <= symbol.size; column += 1) {
      const dark = column < symbol.size && moduleAt(symbol.modules, row, column);
      if (dark && runStart === -1) {
        runStart = column;
      } else if (!dark && runStart !== -1) {
        const width = column - runStart;
        commands.push(`M${runStart + quietZone} ${row + quietZone}h${width}v1h-${width}z`);
        runStart = -1;
      }
    }
  }
  return commands.join('');
}

/**
 * A standalone SVG document for the symbol.
 *
 * The background is an explicit rectangle rather than left to the page, because
 * a scanned symbol needs a light quiet zone whatever it is placed on.
 */
export function qrToSvg(
  symbol: QrSymbol,
  options: { readonly quietZone?: number; readonly title?: string } = {},
): string {
  const quietZone = options.quietZone ?? 4;
  const extent = symbol.size + quietZone * 2;
  const title = options.title ? `<title>${escapeXmlText(options.title)}</title>` : '';
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${extent} ${extent}" ` +
    `width="${extent}" height="${extent}" shape-rendering="crispEdges" role="img">` +
    title +
    `<rect width="${extent}" height="${extent}" fill="#ffffff"/>` +
    `<path d="${qrToSvgPath(symbol, quietZone)}" fill="#000000"/>` +
    `</svg>`
  );
}

/**
 * Escape text for XML content.
 *
 * The title comes from a translated string, so it is interpolated into markup
 * and has to be neutralised. Attribute values are never built this way.
 */
function escapeXmlText(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Remaining modules after the codewords, exposed for the round-trip test. */
export function remainderBits(version: number): number {
  return REMAINDER_BITS[version - 1] ?? 0;
}
