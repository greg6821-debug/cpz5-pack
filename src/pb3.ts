/**
 * pb3.ts — PB3 image decoder (Purple Software custom format).
 * Faithful port of arc_unpacker's:
 *   src/dec/purple_software/pb3_image_decoder.cc  (all 6 sub-versions)
 *   src/dec/purple_software/jbp1.cc               (JPEG-like DCT decoder)
 *
 * Output: { width, height, rgba: Uint8Array } (RGBA, 4 bytes/pixel).
 *
 * pb3 → png: use decodePb3() then encodePng().
 * png → pb3: the game engine accepts raw PNG in .pb3 slots (dual loader),
 *            so just rename .png → .pb3 (no re-encoding needed).
 *
 * NOTE: v6 images reference a BASE image by stem name (from a VFS).
 *       In standalone mode, the base overlay is skipped if the base file
 *       is not found in the same folder. The overlay data is still decoded.
 */

// ---- helpers ----
const rdU32 = (b: Uint8Array, o: number): number =>
  (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const rd16 = (b: Uint8Array, o: number): number => b[o] | (b[o + 1] << 8);
const wrU32 = (b: Uint8Array, o: number, v: number): void => {
  v >>>= 0; b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff;
};

// ============================================================================
// decrypt (pb3_image_decoder.cc: decrypt)
// Undoes a tail-key XOR/sub on bytes [8, 0x34) using key bytes from the end.
// ============================================================================
function pb3Decrypt(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input); // copy
  const size = out.length;
  if (size < 0x2F + 8) return out; // too small, nothing to decrypt
  const tailKeyOff = size - 0x2F;
  const tailKey = out.subarray(tailKeyOff, tailKeyOff + 0x2C); // 44 bytes
  const pairKey = out.subarray(tailKeyOff + 0x2C, tailKeyOff + 0x2C + 2); // 2 bytes
  // encrypted region: bytes [8, 8+0x2C) = [8, 0x34)
  for (let i = 0; i < 0x2C; i += 2) {
    for (let j = 0; j < 2; j++) {
      const idx = 8 + i + j;
      out[idx] ^= pairKey[j];
      out[idx] = (out[idx] - tailKey[i + j]) & 0xff;
    }
  }
  return out;
}

// ============================================================================
// Header (pb3_image_decoder.cc: read_header)
// At offset 0x18: sub_type(u32), main_type(u16), width(u16), height(u16), depth(u16)
// ============================================================================
interface Pb3Header {
  mainType: number;
  subType: number;
  width: number;
  height: number;
  depth: number;
}
function readHeader(buf: Uint8Array): Pb3Header {
  const o = 0x18;
  return {
    subType: rdU32(buf, o),
    mainType: rd16(buf, o + 4),
    width: rd16(buf, o + 6),
    height: rd16(buf, o + 8),
    depth: rd16(buf, o + 10),
  };
}

// ============================================================================
// Custom LZSS (pb3_image_decoder.cc: custom_lzss_decompress)
// 0x800-byte cyclic dictionary, initial position 0x7DE.
// control block: bit flags (1=match, 0=literal)
// data block: for match: u16 (pos=bits>>5, len=(bits&0x1F)+3); for literal: u8
// ============================================================================
function customLzssDecompress(controlBlock: Uint8Array, dataBlock: Uint8Array, outputSize: number): Uint8Array {
  const dict = new Uint8Array(0x800);
  let dictPos = 0x7de;
  const output = new Uint8Array(outputSize);
  let outPos = 0;
  let ctrlOff = 0;
  let dataOff = 0;
  let control = 0;
  let bitMask = 0;
  while (outPos < outputSize) {
    if (!bitMask) {
      control = ctrlOff < controlBlock.length ? controlBlock[ctrlOff++] : 0;
      bitMask = 0x80;
    }
    if (control & bitMask) {
      // match
      if (dataOff + 2 > dataBlock.length) break;
      const tmp = dataBlock[dataOff] | (dataBlock[dataOff + 1] << 8);
      dataOff += 2;
      const lookBehindPos = tmp >> 5;
      let repetitions = (tmp & 0x1f) + 3;
      let src = lookBehindPos;
      while (repetitions-- > 0 && outPos < outputSize) {
        const b = dict[src];
        output[outPos++] = b;
        dict[dictPos] = b;
        dictPos = (dictPos + 1) & 0x7ff;
        src = (src + 1) & 0x7ff;
      }
    } else {
      // literal
      if (dataOff >= dataBlock.length) break;
      const b = dataBlock[dataOff++];
      output[outPos++] = b;
      dict[dictPos] = b;
      dictPos = (dictPos + 1) & 0x7ff;
    }
    bitMask >>= 1;
  }
  return output;
}

// ============================================================================
// CustomBitStream (jbp1.cc: CustomBitStream)
// Reads bits LSB-first from each byte, assembles result MSB-first.
// ============================================================================
class BitStream {
  private data: Uint8Array;
  private pos: number;
  private buffer: number;
  private bitsAvailable: number;
  constructor(data: Uint8Array) {
    this.data = data;
    this.pos = 0;
    this.buffer = 0;
    this.bitsAvailable = 0;
  }
  read(bits: number): number {
    let ret = 0;
    for (let i = 0; i < bits; i++) {
      if (!this.bitsAvailable) {
        this.buffer = this.pos < this.data.length ? this.data[this.pos++] : 0;
        this.bitsAvailable = 8;
      }
      ret = (ret << 1) | (this.buffer & 1);
      this.buffer >>= 1;
      this.bitsAvailable--;
    }
    return ret >>> 0;
  }
}

// ============================================================================
// JBP1 Huffman tree (jbp1.cc: make_tree, read_from_tree)
// ============================================================================
interface Tree {
  base: Uint8Array;        // 0x100 (but only input_size used)
  neighbour: Uint32Array;  // 0x400
  other: Uint32Array;      // 0x102
  root: number;
  inputSize: number;
}

function makeTree(treeInput: Uint8Array, freq: Uint32Array): Tree {
  const base = new Uint8Array(0x100);
  for (let i = 0; i < treeInput.length; i++) base[i] = treeInput[i];
  const neighbour = new Uint32Array(0x400);
  const other = new Uint32Array(0x102);
  const max = 2100000000;
  let size = treeInput.length;
  let c = (~size + 1) | 0; // = -size
  let idx = size + 0x200;

  while (true) {
    // find minimum freq node n
    let n = -1;
    {
      let x = max - 1;
      for (let i = 0; i < size; i++) {
        if (freq[i] < x) { n = i; x = freq[i]; }
      }
    }
    // find second minimum freq node d (≠ n)
    let d = -1;
    {
      let x = max - 1;
      for (let i = 0; i < size; i++) {
        if (i !== n && freq[i] < x) { d = i; x = freq[i]; }
      }
    }
    if (n < 0 || d < 0) break;

    neighbour[idx - 0x200] = n;  // left child
    neighbour[idx] = d;           // right child
    idx++;

    other[n] = size;
    other[d] = c;
    freq[size] = freq[n] + freq[d];
    size++;
    c--;
    freq[n] = max;
    freq[d] = max;
  }

  return { base, neighbour, other, root: size - 1, inputSize: treeInput.length };
}

function readFromTree(tree: Tree, bitStream: BitStream): number {
  let ret = tree.root;
  while (ret >= tree.inputSize) {
    const bit = bitStream.read(1);
    ret = tree.neighbour[(bit << 9) + ret];
  }
  return ret;
}

// ============================================================================
// JBP1 inverse DCT (jbp1.cc: dct)
// 8x8 inverse DCT with fixed-point arithmetic.
// ============================================================================
function idct(dctTable: Int16Array, quant: Int16Array): void {
  // quant offset is 0 (caller passes the right subarray)
  // First pass: process each of 8 rows (lp1 increments by 1 each iteration)
  for (let row = 0; row < 8; row++) {
    const base = row; // dctTable[base + 0..7] is the row (stride 1)
    const qBase = row;

    // Check if all AC coefficients (indices 1-7 in the row) are zero
    const ac0 = dctTable[base + 0x08];
    const ac1 = dctTable[base + 0x10];
    const ac2 = dctTable[base + 0x18];
    const ac3 = dctTable[base + 0x20];
    const ac4 = dctTable[base + 0x28];
    const ac5 = dctTable[base + 0x30];
    const ac6 = dctTable[base + 0x38];

    if (ac0 === 0 && ac1 === 0 && ac2 === 0 && ac3 === 0 && ac4 === 0 && ac5 === 0 && ac6 === 0) {
      // DC only: fill all 8 with DC * quant[0]
      const val = dctTable[base] * quant[qBase];
      dctTable[base + 0x00] = val;
      dctTable[base + 0x08] = val;
      dctTable[base + 0x10] = val;
      dctTable[base + 0x18] = val;
      dctTable[base + 0x20] = val;
      dctTable[base + 0x28] = val;
      dctTable[base + 0x30] = val;
      dctTable[base + 0x38] = val;
    } else {
      let c = quant[qBase + 0x10] * dctTable[base + 0x10];
      let d = quant[qBase + 0x30] * dctTable[base + 0x30];
      let x = Math.floor(((c + d) * 35467) / 65536);
      c = Math.floor((c * 50159) / 65536) + x;
      d = Math.floor((d * -121094) / 65536) + x;
      const a = dctTable[base + 0x00] * quant[qBase + 0x00];
      const b = dctTable[base + 0x20] * quant[qBase + 0x20];
      const w = a + b + c;
      x = a + b - c;
      const y = a - b + d;
      const z = a - b - d;

      const c2 = dctTable[base + 0x38] * quant[qBase + 0x38];
      const d2 = dctTable[base + 0x28] * quant[qBase + 0x28];
      const a2 = dctTable[base + 0x18] * quant[qBase + 0x18];
      const b2 = dctTable[base + 0x08] * quant[qBase + 0x08];
      const n = Math.floor(((a2 + b2 + c2 + d2) * 77062) / 65536);

      const u = n + Math.floor((c2 * 19571) / 65536) + Math.floor(((c2 + a2) * -128553) / 65536) + Math.floor(((c2 + b2) * -58980) / 65536);
      const v = n + Math.floor((d2 * 134553) / 65536) + Math.floor(((d2 + b2) * -25570) / 65536) + Math.floor(((d2 + a2) * -167963) / 65536);
      const t = n + Math.floor((b2 * 98390) / 65536) + Math.floor(((d2 + b2) * -25570) / 65536) + Math.floor(((c2 + b2) * -58980) / 65536);
      const s = n + Math.floor((a2 * 201373) / 65536) + Math.floor(((c2 + a2) * -128553) / 65536) + Math.floor(((d2 + a2) * -167963) / 65536);

      dctTable[base + 0x00] = Math.floor(w + t);
      dctTable[base + 0x38] = Math.floor(w - t);
      dctTable[base + 0x08] = Math.floor(y + s);
      dctTable[base + 0x30] = Math.floor(y - s);
      dctTable[base + 0x10] = Math.floor(z + v);
      dctTable[base + 0x28] = Math.floor(z - v);
      dctTable[base + 0x18] = Math.floor(x + u);
      dctTable[base + 0x20] = Math.floor(x - u);
    }
  }

  // Second pass: process each of 8 columns (lp1 increments by 8 each iteration)
  for (let col = 0; col < 8; col++) {
    const base = col; // dctTable[base + 0, 8, 16, 24, 32, 40, 48, 56] is the column

    const a = dctTable[base + 0];
    const c = dctTable[base + 2];
    const b = dctTable[base + 4];
    const d = dctTable[base + 6];
    const x = Math.floor(((c + d) * 35467) / 65536);
    const cNew = Math.floor((c * 50159) / 65536) + x;
    const dNew = Math.floor((d * -121094) / 65536) + x;
    const w = a + b + cNew;
    const xNew = a + b - cNew;
    const y = a - b + dNew;
    const z = a - b - dNew;

    const d2 = dctTable[base + 5];
    const b2 = dctTable[base + 1];
    const c2 = dctTable[base + 7];
    const a2 = dctTable[base + 3];
    const n = Math.floor(((a2 + b2 + c2 + d2) * 77062) / 65536);

    const s = n + Math.floor((a2 * 201373) / 65536) + Math.floor(((a2 + c2) * -128553) / 65536) + Math.floor(((a2 + d2) * -167963) / 65536);
    const t = n + Math.floor((b2 * 98390) / 65536) + Math.floor(((b2 + d2) * -25570) / 65536) + Math.floor(((b2 + c2) * -58980) / 65536);
    const u = n + Math.floor((c2 * 19571) / 65536) + Math.floor(((b2 + c2) * -58980) / 65536) + Math.floor(((a2 + c2) * -128553) / 65536);
    const v = n + Math.floor((d2 * 134553) / 65536) + Math.floor(((b2 + d2) * -25570) / 65536) + Math.floor(((a2 + d2) * -167963) / 65536);

    dctTable[base + 0] = Math.floor((w + t) / 8);
    dctTable[base + 7] = Math.floor((w - t) / 8);
    dctTable[base + 1] = Math.floor((y + s) / 8);
    dctTable[base + 6] = Math.floor((y - s) / 8);
    dctTable[base + 2] = Math.floor((z + v) / 8);
    dctTable[base + 5] = Math.floor((z - v) / 8);
    dctTable[base + 3] = Math.floor((xNew + u) / 8);
    dctTable[base + 4] = Math.floor((xNew - u) / 8);
  }
}

// ============================================================================
// JBP1 YCbCr→RGB (jbp1.cc: ycc2rgb)
// Converts 4x4 block of YCbCr to RGB using a lookup table for clamping.
// ============================================================================
const YCC_LOOKUP: Uint8Array = (() => {
  const t = new Uint8Array(0x300);
  for (let n = 0; n < 0x100; n++) t[n] = 0;
  for (let n = 0; n < 0x100; n++) t[n + 0x100] = n;
  for (let n = 0; n < 0x100; n++) t[n + 0x200] = 0xff;
  return t;
})();
function clampLookup(idx: number): number {
  if (idx < 0) idx = 0;
  if (idx > 0x2ff) idx = 0x2ff;
  return YCC_LOOKUP[idx];
}

/**
 * ycc2rgb: converts a 4x4 pixel block.
 * Matches C++ jbp1.cc ycc2rgb pointer arithmetic exactly.
 * blockOutput: u8 array; dcOff/acOff: byte offsets into it.
 * iy: Int16Array with Y coefficients (iyOff = base index).
 * cbcr: Int16Array with Cb/Cr coefficients (cbcrOff = base index).
 * stride = block_stride.
 */
function ycc2rgb(
  blockOutput: Uint8Array, dcOff0: number, acOff0: number,
  iy: Int16Array, iyBase: number, cbcr: Int16Array, cbcrBase: number,
  stride: number
): void {
  let dcOff = dcOff0;
  let acOff = acOff0;
  let iyOff = iyBase;
  let cbcrOff = cbcrBase;

  for (let y = 0; y < 4; y++) {
    for (let x = 0; x < 4; x++) {
      const c = cbcr[cbcrOff];
      const d = cbcr[cbcrOff - 64];
      const r = Math.floor((c * 0x166f0) / 65536);
      const g = Math.floor((d * 0x5810) / 65536) + Math.floor((c * 0xb6c0) / 65536);
      const b = Math.floor((d * 0x1c590) / 65536);
      const cw = iy[iyOff + 1] + 0x180;
      const cx = iy[iyOff] + 0x180;
      const cy = iy[iyOff + 8] + 0x180;
      const cz = iy[iyOff + 9] + 0x180;

      blockOutput[dcOff]              = clampLookup(cx + b);
      blockOutput[acOff + 4 - stride] = clampLookup(cw + b);
      blockOutput[acOff]              = clampLookup(cy + b);
      blockOutput[acOff + 4]          = clampLookup(cz + b);
      blockOutput[dcOff + 1]          = clampLookup(cx - g);
      blockOutput[acOff + 5 - stride] = clampLookup(cw - g);
      blockOutput[acOff + 1]          = clampLookup(cy - g);
      blockOutput[acOff + 5]          = clampLookup(cz - g);
      blockOutput[dcOff + 2]          = clampLookup(cx + r);
      blockOutput[acOff + 6 - stride] = clampLookup(cw + r);
      blockOutput[acOff + 2]          = clampLookup(cy + r);
      blockOutput[acOff + 6]          = clampLookup(cz + r);

      iyOff += 2;
      dcOff += 8;
      acOff += 8;
      cbcrOff += 1;
    }
    cbcrOff -= 4;
    dcOff -= 8 * 4;
    acOff -= 8 * 4;
    dcOff += stride * 2;
    acOff += stride * 2;
    iyOff += 8;
    cbcrOff += 8;
  }
}

// ============================================================================
// JBP1 decode_blocks (jbp1.cc: decode_blocks)
// ============================================================================
const ORIGINAL_ORDER = new Uint8Array([
  1,  8,  16, 9,  2,  3,  10, 17,
  24, 32, 25, 18, 11, 4,  5,  12,
  19, 26, 33, 40, 48, 41, 34, 27,
  20, 13, 6,  7,  14, 21, 28, 35,
  42, 49, 56, 57, 50, 43, 36, 29,
  22, 15, 23, 30, 37, 44, 51, 58,
  59, 52, 45, 38, 31, 39, 46, 53,
  60, 61, 54, 47, 55, 62, 63, 0
]);

interface BasicInfo {
  width: number; height: number; depth: number; flags: number; dataOffset: number;
  bitPool1Size: number; bitPool2Size: number;
  blocksWidth: number; blocksHeight: number; blockStride: number;
  xBlockCount: number; yBlockCount: number;
  xBlockSize: number; yBlockSize: number;
}

function decodeBlocks(
  info: BasicInfo,
  treeInput: Uint8Array,
  bitStream1: BitStream, bitStream2: BitStream,
  freqDc: Uint32Array, freqAc: Uint32Array,
  quantY: Int16Array, quantC: Int16Array
): Uint8Array {
  const treeDc = makeTree(treeInput, freqDc);
  const treeAc = makeTree(treeInput, freqAc);

  const tmpSize = info.xBlockCount * info.yBlockCount * 3 * 2;
  const tmp = new Int32Array(tmpSize);

  for (let i = 0; i < tmpSize; i++) {
    const bitCount = readFromTree(treeDc, bitStream1);
    let x = bitStream1.read(bitCount);
    if (bitCount > 0 && x < (1 << (bitCount - 1))) {
      x = x - (1 << bitCount) + 1;
    }
    tmp[i] = x;
    if (i > 0) tmp[i] += tmp[i - 1];
  }

  const blockOutput = new Uint8Array(info.blocksWidth * info.blocksHeight * 4);

  for (let by = 0; by < info.yBlockCount; by++) {
    const targetBase = (info.blocksWidth * 64) * by;
    let target1 = targetBase + 32;
    let target2 = targetBase + info.blockStride * 9;

    for (let bx = 0; bx < info.xBlockCount; bx++) {
      // 6 DCT tables, each 64 entries (Int16Array)
      const dctTables: Int16Array[] = [];
      for (let n = 0; n < 6; n++) {
        const t = new Int16Array(64);
        t[0] = tmp[(by * info.xBlockCount + bx) * 6 + n];
        dctTables.push(t);
      }

      for (let n = 0; n < 6; n++) {
        for (let i = 0; i < 63; ) {
          const bitCount = readFromTree(treeAc, bitStream2);
          if (bitCount === 15) break;
          if (bitCount === 0) {
            let treeInputPos = 0;
            while (bitStream2.read(1)) treeInputPos++;
            i += treeInput[treeInputPos];
          } else {
            let x = bitStream2.read(bitCount);
            if (x < (1 << (bitCount - 1))) {
              x = x - (1 << bitCount) + 1;
            }
            dctTables[n][ORIGINAL_ORDER[i]] = x;
            i++;
          }
        }
      }

      // Apply IDCT (each table is 64 Int16, quant is 64 Int16)
      // The C++ passes dct_table[0] (pointer to 64 s16) and quant_y (pointer to 64 s16).
      // idct operates on 8 rows (stride 1) then 8 columns (stride 8).
      idct(dctTables[0], quantY);
      idct(dctTables[1], quantY);
      idct(dctTables[2], quantY);
      idct(dctTables[3], quantY);
      idct(dctTables[4], quantC);
      idct(dctTables[5], quantC);

      // ycc2rgb calls — 4 calls, each converts a 4x4 block
      ycc2rgb(blockOutput, target1 - 32, target1 - 32 + info.blockStride,
                  dctTables[0], 0, dctTables[5], 0, info.blockStride);
      ycc2rgb(blockOutput, target1, target2 + 32 - info.blockStride * 8,
                  dctTables[1], 0, dctTables[5], 4, info.blockStride);
      ycc2rgb(blockOutput, target1 + (info.blockStride << 3) - 32, target2,
                  dctTables[2], 0, dctTables[5], 32, info.blockStride);
      ycc2rgb(blockOutput, target2 + 32 - info.blockStride, target2 + 32,
                  dctTables[3], 0, dctTables[5], 36, info.blockStride);

      target1 += 64;
      target2 += 64;
    }
  }
  return blockOutput;
}

// ============================================================================
// JBP1 decompress (jbp1.cc: jbp1_decompress)
// Returns raw pixel data in BGR(A) format (depth>>3 bytes per pixel).
// ============================================================================
export function jbp1Decompress(input: Uint8Array): Uint8Array {
  // read_basic_info
  const dataOffset = rdU32(input, 4);
  const flags = rdU32(input, 8);
  // skip 4 bytes at offset 12
  const width = rd16(input, 16);
  const height = rd16(input, 18);
  const depth = rd16(input, 20);
  // skip 6 bytes at offset 22
  const bitPool1Size = rdU32(input, 28);
  const bitPool2Size = rdU32(input, 32);

  const type = (flags >>> 28) & 3;
  let xBlockSize: number, yBlockSize: number;
  if (type === 0) { xBlockSize = 8; yBlockSize = 8; }
  else if (type === 1) { xBlockSize = 16; yBlockSize = 16; }
  else if (type === 2) { xBlockSize = 32; yBlockSize = 16; }
  else throw new Error('Unknown JBP1 type: ' + type);

  const blocksWidth = (width + xBlockSize - 1) & ~(xBlockSize - 1);
  const blocksHeight = (height + yBlockSize - 1) & ~(yBlockSize - 1);
  const blockStride = blocksWidth * 4;
  const xBlockCount = blocksWidth >> 4;
  const yBlockCount = blocksHeight >> 4;

  const info: BasicInfo = {
    width, height, depth, flags, dataOffset,
    bitPool1Size, bitPool2Size,
    blocksWidth, blocksHeight, blockStride,
    xBlockCount, yBlockCount, xBlockSize, yBlockSize,
  };

  // read from dataOffset
  let off = dataOffset;
  const freqDc = new Uint32Array(0x80);
  for (let i = 0; i < 16; i++) { freqDc[i] = rdU32(input, off); off += 4; }
  const freqAc = new Uint32Array(0x80);
  for (let i = 0; i < 16; i++) { freqAc[i] = rdU32(input, off); off += 4; }

  const treeInput = new Uint8Array(16);
  for (let i = 0; i < 16; i++) treeInput[i] = (input[off++] + 1) & 0xff;

  const quantY = new Int16Array(64);
  const quantC = new Int16Array(64);
  if (flags & 0x08000000) {
    for (let i = 0; i < 64; i++) quantY[i] = input[off++];
    for (let i = 0; i < 64; i++) quantC[i] = input[off++];
  }

  const bitPool1 = input.subarray(off, off + bitPool1Size); off += bitPool1Size;
  const bitPool2 = input.subarray(off, off + bitPool2Size); off += bitPool2Size;

  const blockOutput = decodeBlocks(info, treeInput, new BitStream(bitPool1), new BitStream(bitPool2),
                                    freqDc, freqAc, quantY, quantC);

  // Convert block_output to pixel_output
  const channelCount = depth >> 3;
  const pixelOutput = new Uint8Array(width * height * channelCount);
  let pp = 0;
  for (let y = 0; y < height; y++) {
    let bp = info.blockStride * y;
    for (let x = 0; x < width; x++) {
      for (let ch = 0; ch < channelCount; ch++) {
        pixelOutput[pp++] = blockOutput[bp + ch];
      }
      bp += 4;
    }
  }
  return pixelOutput;
}

// ============================================================================
// PB3 unpack sub-versions (pb3_image_decoder.cc: unpack_v1/v2/v3/v5/v6)
// Each returns { width, height, rgba: Uint8Array }
// ============================================================================

// v1: block-based LZSS, per-channel planes (pb3_image_decoder.cc: unpack_v1)
function unpackV1(header: Pb3Header, buf: Uint8Array): { width: number; height: number; rgba: Uint8Array } {
  const channelCount = header.depth >> 3;
  const w = header.width, h = header.height;
  const rgba = new Uint8Array(w * h * 4);

  const mainSizesOffset = rdU32(buf, 0x2c);
  const dataSizesOffset = rdU32(buf, 0x30);

  // read main_sizes and data_sizes
  const mainSizes: number[] = [];
  let off = mainSizesOffset;
  for (let ch = 0; ch < channelCount; ch++) { mainSizes.push(rdU32(buf, off)); off += 4; }
  const dataSizes: number[] = [];
  off = dataSizesOffset;
  for (let ch = 0; ch < channelCount; ch++) { dataSizes.push(rdU32(buf, off)); off += 4; }

  const mainOffsets: number[] = [mainSizesOffset + 4 * channelCount];
  const dataOffsets: number[] = [dataSizesOffset + 4 * channelCount];
  for (let ch = 1; ch < channelCount; ch++) {
    mainOffsets.push(mainOffsets[ch - 1] + mainSizes[ch - 1]);
    dataOffsets.push(dataOffsets[ch - 1] + dataSizes[ch - 1]);
  }

  // PB3 channels are in BGR(A) order (arc_unpacker Pixel = b,g,r,a).
  // Map to RGBA: pb3 ch 0→B(rgba[2]), 1→G(rgba[1]), 2→R(rgba[0]), 3→A(rgba[3]).
  const CH_MAP = [2, 1, 0, 3];

  for (let ch = 0; ch < channelCount; ch++) {
    const rgbaCh = CH_MAP[ch] ?? ch;
    off = mainOffsets[ch];
    const controlBlock1Size = rdU32(buf, off); off += 4;
    const dataBlock1Size = rdU32(buf, off); off += 4;
    const sizeOrig = rdU32(buf, off); off += 4;
    const controlBlock1 = buf.subarray(off, off + controlBlock1Size); off += controlBlock1Size;
    const dataBlock1 = buf.subarray(off, off + dataBlock1Size); off += dataBlock1Size;
    const controlBlock2 = buf.subarray(off, mainOffsets[ch] + mainSizes[ch]);

    const dataBlock2 = buf.subarray(dataOffsets[ch], dataOffsets[ch] + dataSizes[ch]);
    const plane = customLzssDecompress(controlBlock2, dataBlock2, sizeOrig);

    const blockSize = 16;
    let xBlockCount = Math.floor(w / blockSize); if (w % blockSize) xBlockCount++;
    let yBlockCount = Math.floor(h / blockSize); if (h % blockSize) yBlockCount++;

    let cbOff = 0, dbOff = 0;
    let bitMask = 0, control = 0;
    let planeOff = 0;
    for (let by = 0; by < yBlockCount; by++) {
      for (let bx = 0; bx < xBlockCount; bx++) {
        const x1 = bx * blockSize, y1 = by * blockSize;
        const x2 = Math.min(x1 + blockSize, w), y2 = Math.min(y1 + blockSize, h);
        if (!bitMask) { control = cbOff < controlBlock1.length ? controlBlock1[cbOff++] : 0; bitMask = 0x80; }
        if (control & bitMask) {
          const b = dbOff < dataBlock1.length ? dataBlock1[dbOff++] : 0;
          for (let y = y1; y < y2; y++)
            for (let x = x1; x < x2; x++)
              rgba[(y * w + x) * 4 + rgbaCh] = b;
        } else {
          for (let y = y1; y < y2; y++)
            for (let x = x1; x < x2; x++)
              rgba[(y * w + x) * 4 + rgbaCh] = planeOff < plane.length ? plane[planeOff++] : 0;
        }
        bitMask >>= 1;
      }
    }
  }

  if (header.depth !== 32) {
    for (let i = 3; i < rgba.length; i += 4) rgba[i] = 0xff;
  }
  return { width: w, height: h, rgba };
}

// v2: jbp1 + mask (pb3_image_decoder.cc: unpack_v2)
function unpackV2(header: Pb3Header, buf: Uint8Array): { width: number; height: number; rgba: Uint8Array } {
  const w = header.width, h = header.height;
  const maskDataOffset = rdU32(buf, 0x2c);
  const maskDataSize = rdU32(buf, 0x30);
  const curPos = 0x2c + 8; // after reading 2 u32s at 0x2c and 0x30
  const jbp1DataSize = maskDataOffset - curPos;
  const jbp1Data = buf.subarray(curPos, curPos + jbp1DataSize);
  const maskData = buf.subarray(maskDataOffset, maskDataOffset + maskDataSize);

  // jbp1 → BGR888
  const bgr = jbp1Decompress(jbp1Data); // 3 bytes/pixel: B,G,R
  const rgba = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    rgba[i * 4 + 0] = bgr[i * 3 + 2]; // R
    rgba[i * 4 + 1] = bgr[i * 3 + 1]; // G
    rgba[i * 4 + 2] = bgr[i * 3 + 0]; // B
    rgba[i * 4 + 3] = 0xff;
  }

  // mask: RLE decode
  const mask = new Uint8Array(w * h);
  let mOff = 0, mPos = 0;
  while (mOff < maskData.length && mPos < mask.length) {
    const control = maskData[mOff++];
    if (control === 0 || control === 0xff) {
      const count = mOff < maskData.length ? maskData[mOff++] : 0;
      for (let i = 0; i < count && mPos < mask.length; i++) mask[mPos++] = control;
    } else {
      mask[mPos++] = control;
    }
  }
  for (let i = 0; i < w * h; i++) rgba[i * 4 + 3] = mask[i];

  return { width: w, height: h, rgba };
}

// v3: jbp1 only (pb3_image_decoder.cc: unpack_v3)
function unpackV3(header: Pb3Header, buf: Uint8Array): { width: number; height: number; rgba: Uint8Array } {
  const w = header.width, h = header.height;
  const jbp1Data = buf.subarray(0x34);
  const bgr = jbp1Decompress(jbp1Data); // BGR888
  const rgba = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    rgba[i * 4 + 0] = bgr[i * 3 + 2];
    rgba[i * 4 + 1] = bgr[i * 3 + 1];
    rgba[i * 4 + 2] = bgr[i * 3 + 0];
    rgba[i * 4 + 3] = 0xff;
  }
  return { width: w, height: h, rgba };
}

// v5: per-channel LZSS + delta coding (pb3_image_decoder.cc: unpack_v5)
function unpackV5(header: Pb3Header, buf: Uint8Array): { width: number; height: number; rgba: Uint8Array } {
  const channelCount = header.depth >> 3;
  const w = header.width, h = header.height;
  const rgba = new Uint8Array(w * h * 4);

  // read channel offsets at 0x34
  const controlOffsets: number[] = [];
  const dataOffsets: number[] = [];
  let off = 0x34;
  for (let ch = 0; ch < channelCount; ch++) {
    controlOffsets.push(0x54 + rdU32(buf, off)); off += 4;
    dataOffsets.push(0x54 + rdU32(buf, off)); off += 4;
  }

  const controlSizes: number[] = [];
  const dataSizes: number[] = [];
  for (let ch = 1; ch < channelCount; ch++) {
    controlSizes.push(controlOffsets[ch] - controlOffsets[ch - 1]);
    dataSizes.push(dataOffsets[ch] - dataOffsets[ch - 1]);
  }
  controlSizes.push(buf.length - controlOffsets[channelCount - 1]);
  dataSizes.push(buf.length - dataOffsets[channelCount - 1]);

  // PB3 channels are BGR(A) order (arc_unpacker Pixel = b,g,r,a).
  const CH_MAP = [2, 1, 0, 3];
  for (let ch = 0; ch < channelCount; ch++) {
    const rgbaCh = CH_MAP[ch] ?? ch;
    const controlBlock = buf.subarray(controlOffsets[ch], controlOffsets[ch] + controlSizes[ch]);
    const dataBlock = buf.subarray(dataOffsets[ch], dataOffsets[ch] + dataSizes[ch]);
    const plane = customLzssDecompress(controlBlock, dataBlock, w * h);

    let acc = 0;
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        acc = (acc + plane[y * w + x]) & 0xff;
        rgba[(y * w + x) * 4 + rgbaCh] = acc;
      }
    }
  }

  if (header.depth !== 32) {
    for (let i = 3; i < rgba.length; i += 4) rgba[i] = 0xff;
  }
  return { width: w, height: h, rgba };
}

// v6: base image overlay + proxy block LZSS (pb3_image_decoder.cc: unpack_v6)
// NOTE: base image loading via VFS is skipped (standalone tool).
function unpackV6(header: Pb3Header, buf: Uint8Array, baseDir?: string): { width: number; height: number; rgba: Uint8Array } {
  const w = header.width, h = header.height;
  const rgba = new Uint8Array(w * h * 4);

  // read base stem (XOR'd name at 0x34, 0x20 bytes)
  const NAME_KEY = new Uint8Array([0xA6, 0x75, 0xF3, 0x9C, 0xC5, 0x69, 0x78, 0xA3, 0x3E, 0xA5, 0x4F, 0x79, 0x59, 0xFE, 0x3A, 0xC7]);
  const baseStemBytes = new Uint8Array(0x20);
  for (let i = 0; i < 0x20; i++) baseStemBytes[i] = buf[0x34 + i] ^ NAME_KEY[i % NAME_KEY.length];
  let baseStem = '';
  for (let i = 0; i < 0x20; i++) { if (baseStemBytes[i] === 0) break; baseStem += String.fromCharCode(baseStemBytes[i]); }

  // Try to load base image from same folder (optional)
  if (baseDir && baseStem) {
    try {
      const fs = require('node:fs');
      const path = require('node:path');
      for (const ext of ['.pb3', '.png']) {
        const baseFile = path.join(baseDir, baseStem + ext);
        if (fs.existsSync(baseFile)) {
          const baseData = fs.readFileSync(baseFile);
          if (ext === '.png') {
            // decode PNG → RGBA (simple — or skip if no decoder)
            // For now, skip PNG loading; user can convert separately
          } else {
            const baseImg = decodePb3(new Uint8Array(baseData), baseDir);
            rgba.set(baseImg.rgba);
          }
          break;
        }
      }
    } catch { /* ignore base load errors */ }
  }

  // decode overlay
  const sizeOrig = rdU32(buf, 0x18);
  const controlBlockOffset = 0x20 + rdU32(buf, 0x0c);
  const dataBlockOffset = controlBlockOffset + rdU32(buf, 0x2c);
  const dataBlockSize = rdU32(buf, 0x30);
  const controlBlockSize = dataBlockOffset - controlBlockOffset;

  const controlBlock1 = buf.subarray(controlBlockOffset, controlBlockOffset + controlBlockSize);
  const dataBlock1 = buf.subarray(dataBlockOffset, dataBlockOffset + dataBlockSize);
  const proxyBlock = customLzssDecompress(controlBlock1, dataBlock1, sizeOrig);

  // read sub-blocks from proxy block
  let pp = 0;
  const controlBlock2Size = rdU32(proxyBlock, pp); pp += 4;
  const dataBlock2Size = rdU32(proxyBlock, pp); pp += 4;
  const controlBlock2 = proxyBlock.subarray(pp, pp + controlBlock2Size); pp += controlBlock2Size;
  const dataBlock2 = proxyBlock.subarray(pp, pp + dataBlock2Size); pp += dataBlock2Size;

  const blockSize = 8;
  let xBlockCount = Math.floor(w / blockSize); if (w % blockSize) xBlockCount++;
  let yBlockCount = Math.floor(h / blockSize); if (h % blockSize) yBlockCount++;

  let cbOff = 0, dbOff = 0;
  let bitMask = 0, control = 0;
  for (let by = 0; by < yBlockCount; by++) {
    for (let bx = 0; bx < xBlockCount; bx++) {
      const x1 = bx * blockSize, y1 = by * blockSize;
      const x2 = Math.min(x1 + blockSize, w), y2 = Math.min(y1 + blockSize, h);
      if (!bitMask) { control = cbOff < controlBlock2.length ? controlBlock2[cbOff++] : 0; bitMask = 0x80; }
      if (!(control & bitMask)) {
        for (let y = y1; y < y2; y++) {
          for (let x = x1; x < x2; x++) {
            const idx = (y * w + x) * 4;
            // dataBlock2 is BGRA8888 (B,G,R,A byte order) → convert to RGBA
            const b = dbOff < dataBlock2.length ? dataBlock2[dbOff++] : 0;
            const g = dbOff < dataBlock2.length ? dataBlock2[dbOff++] : 0;
            const r = dbOff < dataBlock2.length ? dataBlock2[dbOff++] : 0;
            const a = dbOff < dataBlock2.length ? dataBlock2[dbOff++] : 0;
            rgba[idx + 0] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = a;
          }
        }
      }
      bitMask >>= 1;
    }
  }

  return { width: w, height: h, rgba };
}

// ============================================================================
// Main entry: decodePb3
// ============================================================================
export function decodePb3(input: Uint8Array, baseDir?: string): { width: number; height: number; rgba: Uint8Array } {
  // check magic "PB3B"
  if (input.length < 4 || input[0] !== 0x50 || input[1] !== 0x42 || input[2] !== 0x33 || input[3] !== 0x42) {
    throw new Error('Not a PB3B file (magic mismatch)');
  }
  const decrypted = pb3Decrypt(input);
  const header = readHeader(decrypted);

  if (header.mainType === 1 && header.subType === 0x10) return unpackV1(header, decrypted);
  if (header.mainType === 2) return unpackV2(header, decrypted);
  if (header.mainType === 3) return unpackV3(header, decrypted);
  if (header.mainType === 5) return unpackV5(header, decrypted);
  if (header.mainType === 6) return unpackV6(header, decrypted, baseDir);

  throw new Error(`Unsupported PB3 type: ${header.mainType}.${header.subType}`);
}

/** Read just the header info (for inspection without full decode). */
export function pb3Info(input: Uint8Array): { mainType: number; subType: number; width: number; height: number; depth: number } {
  const decrypted = pb3Decrypt(input);
  return readHeader(decrypted);
}
