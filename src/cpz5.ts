/**
 * cpz5.ts — Core CPZ5/CPZ6 archive packer/unpacker library.
 *
 * Faithful port of arc_unpacker's purple_software/cpz5 decoder
 * (https://github.com/vn-tools/arc_unpacker, GPL-3.0) PLUS the exact
 * mathematical inverses of every transform (encoders), so a repacked
 * archive is byte-compatible with the original when keys are reused.
 *
 * Target game: happymaher (regret end) — Purple Software.
 *
 * All arithmetic is mod 2^32 (use `>>> 0` to keep unsigned).
 * All multi-byte archive fields are little-endian.
 *
 * This file has NO runtime dependencies (only `TextDecoder` for SJIS paths)
 * so it runs identically under Bun, Node, and Next.js API routes.
 */

// ----------------------------------------------------------------------------
// 32-bit helpers
// ----------------------------------------------------------------------------
export const u32 = (n: number): number => n >>> 0;
export const rotl32 = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));
export const rotr32 = (x: number, n: number): number => u32((x >>> n) | (x << (32 - n)));

/** read LE u32 from Uint8Array at byte offset */
export const rdU32 = (b: Uint8Array, o: number): number =>
  (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
/** read LE u64 from Uint8Array at byte offset (as number, safe < 2^53) */
export const rdU64 = (b: Uint8Array, o: number): number => {
  const lo = rdU32(b, o);
  const hi = rdU32(b, o + 4);
  return hi * 0x100000000 + lo;
};
/** write LE u32 */
export const wrU32 = (b: Uint8Array, o: number, v: number): void => {
  v = v >>> 0;
  b[o] = v & 0xff;
  b[o + 1] = (v >>> 8) & 0xff;
  b[o + 2] = (v >>> 16) & 0xff;
  b[o + 3] = (v >>> 24) & 0xff;
};
/** write LE u64 */
export const wrU64 = (b: Uint8Array, o: number, v: number): void => {
  wrU32(b, o, v >>> 0);
  wrU32(b, o + 4, Math.floor(v / 0x100000000) >>> 0);
};

const hexToBytes = (hex: string): Uint8Array => {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
};

// ----------------------------------------------------------------------------
// MD5 with custom initial state (arc_unpacker: algo::crypt::md5(input, iv))
// Standard MD5 padding/schedule/rounds, only A,B,C,D replaced after Init.
// ----------------------------------------------------------------------------
/** MD5 with custom initial state (arc_unpacker algo::crypt::md5(input, iv)). Exported for testing. */
export function md5CustomIV(input: Uint8Array, iv: [number, number, number, number]): Uint8Array {
  // init state from IV
  let a = iv[0] >>> 0, b = iv[1] >>> 0, c = iv[2] >>> 0, d = iv[3] >>> 0;

  // padding
  const origLen = input.length;
  const bitLen = Math.imul(origLen, 8); // bits (mod 2^64; assume < 2^32 bits)
  const withPad = origLen + 1;
  const padLen = (56 - (withPad % 64) + 64) % 64;
  const total = withPad + padLen + 8;
  const msg = new Uint8Array(total);
  msg.set(input, 0);
  msg[origLen] = 0x80;
  // 64-bit LE length in bits
  wrU32(msg, total - 8, bitLen >>> 0);
  wrU32(msg, total - 4, Math.floor(bitLen / 0x100000000) >>> 0);

  // MD5 constants — standard RFC 1321 (T hardcoded to avoid Math.sin precision drift)
  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const T = new Uint32Array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
  ]);

  const K = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
  ];

  const x = new Uint32Array(16);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) x[i] = rdU32(msg, off + i * 4);
    let aa = a, bb = b, cc = c, dd = d;
    for (let i = 0; i < 64; i++) {
      let f: number; let g: number;
      if (i < 16) { f = (bb & cc) | (~bb & dd); g = i; }
      else if (i < 32) { f = (dd & bb) | (~dd & cc); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = bb ^ cc ^ dd; g = (3 * i + 5) % 16; }
      else { f = cc ^ (bb | ~dd); g = (7 * i) % 16; }
      f = u32(u32(f + aa) + T[i]);
      f = u32(u32(f + x[g]));
      aa = dd; dd = cc; cc = bb;
      bb = u32(bb + rotl32(f, S[i]));
    }
    a = u32(a + aa); b = u32(b + bb); c = u32(c + cc); d = u32(d + dd);
  }
  const out = new Uint8Array(16);
  wrU32(out, 0, a); wrU32(out, 4, b); wrU32(out, 8, c); wrU32(out, 12, d);
  return out;
}

// ----------------------------------------------------------------------------
// Plugin definitions (from arc_unpacker plugin.cc)
// ----------------------------------------------------------------------------
export interface Plugin {
  name: string;
  secret: Uint8Array;            // 96 bytes
  hash_permutation: [number, number, number, number];
  hash_iv: [number, number, number, number];
  hash_xor: [number, number, number, number];
  hash_add: [number, number, number, number];
  crypt_23_mul: number;
  crypt_1a: { add1: number; add2: number; tail_sub: number };
  crypt_1c: { addends: [number, number, number, number]; init_key: number };
  crypt_3: { start_pos: number; tail_xor: number };
}

// Exact bytes extracted from arc_unpacker src/dec/purple_software/cpz5/plugin.cc
// (verified via Python regex extraction — do NOT retype by hand)
const SECRET_5V1 = hexToBytes(
  '89F090CD82B782E988AB82A28E7182CD' +
  '838A835282AA82A88E64927582AB82B5' +
  '82BF82E182A282DC82B781428EF482ED' +
  '82EA82BF82E182A282DC82B782E68160' +
  '814182C682A282A482A982E082A48EF4' +
  '82C182BF82E182A282DC82B582BD81F4'
);
const SECRET_5V2 = hexToBytes(
  '89F090CD82B782E988AB82A28E7182CD' +
  '838A835282AA82A88E64927582AB82B5' +
  '82BF82E182A282DC82B7814283818362' +
  '814982A982ED82A282A282C682A98CBE' +
  '82C182C482E08B9682B582C482A082B0' +
  '82C882A282F182BE82A982E7829F8149'
);
const SECRET_V6 = SECRET_5V1; // identical to 5v1 per arc_unpacker source

function base5Plugin(): Plugin {
  return {
    name: '',
    secret: SECRET_5V1,
    hash_permutation: [0, 0, 0, 0],
    hash_iv: [0, 0, 0, 0],
    hash_xor: [0, 0, 0, 0],
    hash_add: [0, 0, 0, 0],
    crypt_23_mul: 0,
    crypt_1a: { add1: 0x784c5962, add2: 0x01010101, tail_sub: 0x79 },
    crypt_1c: { addends: [0, 0x112233, 0, 0x34258765], init_key: 0x2a65cb4e },
    crypt_3: { start_pos: 9, tail_xor: 0 },
  };
}

export function plugin5v1(): Plugin {
  const p = base5Plugin();
  p.name = '5v1';
  p.secret = SECRET_5V1;
  p.hash_permutation = [3, 1, 2, 0];
  p.hash_iv = [0xc74a2b01, 0xe7c8ab8f, 0xd8bedc4e, 0x7302a4c5];
  p.hash_xor = [0, 0, 0, 0];
  p.hash_add = [0, 0, 0, 0];
  p.crypt_3.tail_xor = 0xbc;
  p.crypt_23_mul = 0x1a743125;
  return p;
}

export function plugin5v2(): Plugin {
  const p = base5Plugin();
  p.name = '5v2';
  p.secret = SECRET_5V2;
  p.hash_permutation = [1, 2, 3, 0];
  p.hash_iv = [0x53fe9b2c, 0xf2c93ea8, 0xee81ba59, 0xa2c8973e];
  p.hash_xor = [0x49875325, 0, 0xad7948b7, 0];
  p.hash_add = [0, 0x54f46d7d, 0, 0x1d0638ad];
  p.crypt_3.tail_xor = 0xcb;
  p.crypt_23_mul = 0x1a740235;
  return p;
}

export function plugin6(): Plugin {
  const p: Plugin = {
    name: '6',
    secret: SECRET_V6,
    hash_permutation: [2, 1, 0, 3],
    hash_iv: [0xc74a2b01, 0xe7c8ab8f, 0xd8bedc4e, 0x7302a4c5],
    hash_xor: [0x45a76c2f, 0, 0x79abe8ad, 0],
    hash_add: [0, 0xa45e8035, 0, 0xe3f7a9e5],
    crypt_23_mul: 0x1a74f195,
    crypt_1a: { add1: 0x784c5062, add2: 0x01010101, tail_sub: 0x7d },
    crypt_1c: { addends: [0, 0x11003322, 0, 0x34216785], init_key: 0x2a65cb4f },
    crypt_3: { start_pos: 10, tail_xor: 0xae },
  };
  return p;
}

// ----------------------------------------------------------------------------
// get_hash (crypt.cc)
// ----------------------------------------------------------------------------
export function getHash(plugin: Plugin, md5Dwords: [number, number, number, number]): [number, number, number, number] {
  const input = new Uint8Array(16);
  wrU32(input, 0, md5Dwords[0]); wrU32(input, 4, md5Dwords[1]);
  wrU32(input, 8, md5Dwords[2]); wrU32(input, 12, md5Dwords[3]);
  const hashBytes = md5CustomIV(input, plugin.hash_iv);
  const hashDwords: [number, number, number, number] = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) hashDwords[i] = rdU32(hashBytes, i * 4);
  const result: [number, number, number, number] = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) {
    result[i] = u32(hashDwords[plugin.hash_permutation[i]]);
    result[i] = u32(result[i] ^ plugin.hash_xor[i]);
    result[i] = u32(result[i] + plugin.hash_add[i]);
  }
  return result;
}

// ----------------------------------------------------------------------------
// permutation table for crypt_2 and crypt_3 (crypt.cc)
// ----------------------------------------------------------------------------
function getByteTable(plugin: Plugin, key: number, seed: number): Uint8Array {
  const table = new Uint8Array(256);
  for (let i = 0; i < 256; i++) table[i] = i;
  let k = key >>> 0;
  for (let i = 0; i < 256; i++) {
    const a = (k >>> 16) & 0xff, b = k & 0xff, c = (k >>> 8) & 0xff, dd = (k >>> 24) & 0xff;
    const t1 = table[a]; table[a] = table[b]; table[b] = t1;
    const t2 = table[c]; table[c] = table[dd]; table[dd] = t2;
    k = u32(u32(Math.imul(rotr32(k, 2), plugin.crypt_23_mul)) + seed);
  }
  return table;
}
function invertTable(table: Uint8Array): Uint8Array {
  const inv = new Uint8Array(256);
  for (let i = 0; i < 256; i++) inv[table[i]] = i;
  return inv;
}

// ----------------------------------------------------------------------------
// crypt_1a  (whole-index layer; inverse of decrypt_1a)
// decrypt: P = rotr((table[pos]^C)+add1, shift) + add2   [words]
// encrypt: C = (rotl(P-add2,shift) - add1) ^ table[pos]
// ----------------------------------------------------------------------------
function crypt1aShift(key: number): number {
  let shift = key >>> 0;
  for (let i = 0; i < 3; i++) shift = u32((shift >>> 8) ^ key);
  shift = ((shift ^ 0xfb) & 0x0f) + 7;
  return shift;
}
function crypt1aTable(plugin: Plugin, key: number): Uint32Array {
  const t = new Uint32Array(24);
  const secretU32 = new Uint32Array(24);
  for (let i = 0; i < 24; i++) secretU32[i] = rdU32(plugin.secret, i * 4);
  for (let i = 0; i < 24; i++) t[i] = u32(secretU32[i] - key);
  return t;
}
/** in-place; encode=true produces ciphertext from plaintext, encode=false = decrypt */
export function crypt1a(buf: Uint8Array, plugin: Plugin, key: number, encode: boolean): void {
  const table = crypt1aTable(plugin, key);
  const shift = crypt1aShift(key);
  const words = buf.length >> 2;
  const tail = buf.length & 3;
  let pos = 5;
  const add1 = plugin.crypt_1a.add1, add2 = plugin.crypt_1a.add2, tailSub = plugin.crypt_1a.tail_sub;
  for (let i = 0; i < words; i++) {
    const o = i * 4;
    const c = rdU32(buf, o);
    let out: number;
    if (encode) {
      const tmp2 = u32(rotl32(u32(c - add2), shift) - add1); // tmp2 = rotl(P-add2,shift); tmp1 = tmp2-add1
      out = u32(tmp2 ^ table[pos]);
    } else {
      const tmp1 = u32(table[pos] ^ c);
      const tmp2 = u32(tmp1 + add1);
      out = u32(rotr32(tmp2, shift) + add2);
    }
    wrU32(buf, o, out);
    pos = (pos + 1) % 24;
  }
  for (let i = 0; i < tail; i++) {
    const o = words * 4 + i;
    const v = buf[o];
    const tb = (table[pos] >>> (4 * (3 - i))) & 0xff;
    let out: number;
    if (encode) out = u32((u32(v + tailSub)) ^ tb) & 0xff;       // C = (P+tailSub) ^ tb
    else out = u32((tb ^ v) - tailSub) & 0xff;                    // P = (tb^C) - tailSub
    buf[o] = out;
    pos = (pos + 1) % 24;
  }
}

// ----------------------------------------------------------------------------
// crypt_1b  (dir-table layer; inverse of decrypt_1b)
// decrypt: P = rotl((C^table[pos]) - 0x4A91C262, 3) - seed
// encrypt: C = (rotr(P+seed,3) + 0x4A91C262) ^ table[pos]
// ----------------------------------------------------------------------------
function crypt1bTable(key: number, hash: [number, number, number, number]): Uint32Array {
  const addends = [0x76a3bf29, 0, 0x10000000, 0];
  const t = new Uint32Array(4);
  for (let i = 0; i < 4; i++) t[i] = u32(hash[i] ^ (u32(key + addends[i])));
  return t;
}
export function crypt1b(buf: Uint8Array, key: number, hash: [number, number, number, number], encode: boolean): void {
  const table = crypt1bTable(key, hash);
  const words = buf.length >> 2;
  const tail = buf.length & 3;
  let pos = 0;
  let seed = 0x76548aef;
  for (let i = 0; i < words; i++) {
    const o = i * 4;
    const v = rdU32(buf, o);
    let out: number;
    if (encode) {
      const tmp = rotr32(u32(v + seed), 3);             // tmp = rotr(P+seed,3)
      out = u32(u32(tmp + 0x4a91c262) ^ table[pos]);     // C = (tmp+const)^table
    } else {
      const tmp = u32((u32(v ^ table[pos])) - 0x4a91c262);
      out = u32(rotl32(tmp, 3) - seed); // C++ decrypt_1b: rotl(tmp,3) - seed
    }
    wrU32(buf, o, out);
    pos = (pos + 1) % 4;
    seed = u32(seed + 0x10fb562a);
  }
  for (let i = 0; i < tail; i++) {
    const o = words * 4 + i;
    const v = buf[o];
    const tb = (table[pos] >>> 6) & 0xff;
    let out: number;
    if (encode) out = u32((u32(v - 0x37)) ^ tb) & 0xff;       // C = (P-0x37)^tb
    else out = u32((tb ^ v) + 0x37) & 0xff;                    // P = (tb^C)+0x37
    buf[o] = out;
    pos = (pos + 1) % 4;
  }
}

// ----------------------------------------------------------------------------
// crypt_1c  (file-table layer; inverse of decrypt_1c)
// decrypt: P = rotl((C^table[pos]) - seed, 2) + 0x37A19E8B
// encrypt: C = (rotr(P-0x37A19E8B,2) + seed) ^ table[pos]
// ----------------------------------------------------------------------------
function crypt1cTable(plugin: Plugin, key: number, hash: [number, number, number, number]): Uint32Array {
  const t = new Uint32Array(4);
  for (let i = 0; i < 4; i++) t[i] = u32(hash[i] ^ (u32(key + plugin.crypt_1c.addends[i])));
  return t;
}
export function crypt1c(buf: Uint8Array, plugin: Plugin, key: number, hash: [number, number, number, number], encode: boolean): void {
  const table = crypt1cTable(plugin, key, hash);
  const words = buf.length >> 2;
  const tail = buf.length & 3;
  let pos = 0;
  let seed = plugin.crypt_1c.init_key;
  for (let i = 0; i < words; i++) {
    const o = i * 4;
    const v = rdU32(buf, o);
    let out: number;
    if (encode) {
      const tmp = rotr32(u32(v - 0x37a19e8b), 2);
      out = u32(u32(tmp + seed) ^ table[pos]);
    } else {
      const tmp = u32((u32(v ^ table[pos])) - seed);
      out = u32(rotl32(tmp, 2) + 0x37a19e8b);
    }
    wrU32(buf, o, out);
    pos = (pos + 1) % 4;
    seed = u32(seed - 0x139fa9b);
  }
  for (let i = 0; i < tail; i++) {
    const o = words * 4 + i;
    const v = buf[o];
    const tb = (table[pos] >>> 4) & 0xff;
    let out: number;
    if (encode) out = u32((u32(v - 0x05)) ^ tb) & 0xff;
    else out = u32((tb ^ v) + 0x05) & 0xff;
    buf[o] = out;
    pos = (pos + 1) % 4;
  }
}

// ----------------------------------------------------------------------------
// crypt_2  (byte-substitution layer; inverse of decrypt_2)
// decrypt: P = table[C ^ px]
// encrypt: C = inv_table[P] ^ px
// ----------------------------------------------------------------------------
export function crypt2(buf: Uint8Array, plugin: Plugin, key: number, seed: number, permutationXor: number, encode: boolean): void {
  const table = getByteTable(plugin, key, seed);
  if (!encode) {
    for (let i = 0; i < buf.length; i++) buf[i] = table[buf[i] ^ permutationXor];
  } else {
    const inv = invertTable(table);
    for (let i = 0; i < buf.length; i++) buf[i] = u32(inv[buf[i]] ^ permutationXor) & 0xff;
  }
}

// ----------------------------------------------------------------------------
// crypt_3  (file-data layer; inverse of decrypt_3)
// decrypt word i: P = hash[yak&3] ^ ((C ^ tmp2 ^ tmp3) - entryKey); yak += P + entryKey
// encrypt word i: C = ((P ^ hash[yak&3]) + entryKey) ^ tmp2 ^ tmp3; yak += P + entryKey
// ----------------------------------------------------------------------------
export function crypt3(buf: Uint8Array, plugin: Plugin, key: number, seed: number, hash: [number, number, number, number], entryKey: number, encode: boolean): void {
  // table = getByteTable(plugin, key=hash[3], seed=main_key)
  const table = getByteTable(plugin, key, seed);
  // yet_another_table (24 u32): yat_byte[i] = table[secret[i]] ^ (hash[1]>>2); then yat[i] ^= entryKey
  const yat = new Uint32Array(24);
  const yatBytes = new Uint8Array(yat.buffer, 0, 96); // LE view
  const hash1shr = (hash[1] >>> 2) & 0xff;
  for (let i = 0; i < 96; i++) yatBytes[i] = u32(table[plugin.secret[i]] ^ hash1shr) & 0xff;
  for (let i = 0; i < 24; i++) yat[i] = u32(yat[i] ^ entryKey);

  let pos = plugin.crypt_3.start_pos;
  let yak = 0x2547a39e;
  const words = buf.length >> 2;
  const tail = buf.length & 3;

  for (let i = 0; i < words; i++) {
    const o = i * 4;
    const tmp2 = yat[pos & 0x0f] >>> 1;
    const tmp3 = yat[(yak >>> 6) & 0x0f];
    let out: number;
    if (encode) {
      const p = rdU32(buf, o);
      out = u32(u32((u32(p ^ hash[yak & 3])) + entryKey) ^ tmp2 ^ tmp3);
      yak = u32(u32(yak + p) + entryKey);
    } else {
      const c = rdU32(buf, o);
      const finalTmp = u32(u32(c ^ tmp2) ^ tmp3);
      const p = u32(hash[yak & 3] ^ u32(finalTmp - entryKey));
      out = p;
      yak = u32(u32(yak + p) + entryKey);
    }
    wrU32(buf, o, out);
    pos = pos + 1;
  }
  // tail bytes: decrypt P = table[C ^ tail_xor]; encrypt C = inv[P] ^ tail_xor
  for (let i = 0; i < tail; i++) {
    const o = words * 4 + i;
    if (encode) {
      const inv = invertTable(table);
      buf[o] = u32(inv[buf[o]] ^ plugin.crypt_3.tail_xor) & 0xff;
    } else {
      buf[o] = table[buf[o] ^ plugin.crypt_3.tail_xor];
    }
  }
}

// ----------------------------------------------------------------------------
// Header
// ----------------------------------------------------------------------------
export interface CpzHeader {
  version: 5 | 6;
  magic: string;
  dirCount: number;
  dirTableSize: number;
  fileTableSize: number;
  md5Dwords: [number, number, number, number];
  mainKey: number;
  extraKey: number;
  tableSize: number;
  dataStart: number;
  raw: Uint8Array; // original 64-byte header (for verbatim reuse)
}

const HEADER_XOR = {
  v5: {
    dirCount: 0xfe3a53d9, dirTableSize: 0x37f298e7, fileTableSize: 0x7a6f3a2c,
    md5: [0x43de7c19, 0xcc65f415, 0xd016a93c, 0x97a3ba9a], mainKey: 0xae7d39bf,
  },
  v6: {
    dirCount: 0xfe3a53da, dirTableSize: 0x37f298e8, fileTableSize: 0x7a6f3a2d,
    md5: [0x43de7c1a, 0xcc65f416, 0xd016a93d, 0x97a3ba9b], mainKey: 0xae7d39b7,
  },
};

export function readHeader(buf: Uint8Array): CpzHeader {
  const magic = Buffer.from(buf.slice(0, 4)).toString('latin1');
  let version: 5 | 6;
  if (magic === 'CPZ5') version = 5;
  else if (magic === 'CPZ6') version = 6;
  else throw new Error(`Not a CPZ5/CPZ6 archive (magic=${JSON.stringify(magic)})`);
  const x = HEADER_XOR[version === 5 ? 'v5' : 'v6'];
  const dirCount = u32(rdU32(buf, 4) ^ x.dirCount);
  const dirTableSize = u32(rdU32(buf, 8) ^ x.dirTableSize);
  const fileTableSize = u32(rdU32(buf, 12) ^ x.fileTableSize);
  // skip 16 bytes (offsets 16..31)
  const md5: [number, number, number, number] = [
    u32(rdU32(buf, 32) ^ x.md5[0]),
    u32(rdU32(buf, 36) ^ x.md5[1]),
    u32(rdU32(buf, 40) ^ x.md5[2]),
    u32(rdU32(buf, 44) ^ x.md5[3]),
  ];
  const mainKey = u32(rdU32(buf, 48) ^ x.mainKey);
  let extraKey = 0;
  if (version === 6) {
    const tmp1 = u32(rdU32(buf, 52) ^ 0xfb73a956);
    const tmp2 = u32(rdU32(buf, 56) ^ 0x37acf832);
    extraKey = u32(u32(Math.imul(rotr32(tmp2, 5), 0x7da8f173)) + 0x13712765);
  }
  const tableSize = u32(dirTableSize + fileTableSize);
  const dataStart = 64 + tableSize;
  return {
    version, magic, dirCount, dirTableSize, fileTableSize,
    md5Dwords: md5, mainKey, extraKey, tableSize, dataStart,
    raw: buf.slice(0, 64),
  };
}

// ----------------------------------------------------------------------------
// SJIS path decoding (for display & filenames only; archive keeps raw SJIS bytes)
// ----------------------------------------------------------------------------
let _sjisDecoder: TextDecoder | null = null;
function sjisDecoder(): TextDecoder {
  if (!_sjisDecoder) {
    try { _sjisDecoder = new TextDecoder('shift_jis'); }
    catch { _sjisDecoder = new TextDecoder('latin1'); } // fallback (paths may look off but bytes preserved)
  }
  return _sjisDecoder;
}
export function decodeSjis(bytes: Uint8Array): string {
  return sjisDecoder().decode(bytes);
}
/** take bytes up to first 0x00 */
function readToZero(buf: Uint8Array, off: number): { bytes: Uint8Array; next: number } {
  let end = off;
  while (end < buf.length && buf[end] !== 0) end++;
  return { bytes: buf.slice(off, end), next: end + 1 };
}

// ----------------------------------------------------------------------------
// Parsed archive
// ----------------------------------------------------------------------------
export interface DirInfo {
  indexLength: number;      // entry_size (bytes)
  fileCount: number;
  fileTableOffset: number;  // within file-table region
  fileTableMainKey: number; // dir key
  pathBytes: Uint8Array;    // raw SJIS dir name
  pathStr: string;          // decoded
  fileTableSize: number;    // computed
  // raw decrypted dir-entry bytes (indexLength) — for verbatim reuse on repack
  rawEntry: Uint8Array;
}

export interface FileEntry {
  dirIndex: number;
  indexLength: number;     // entry_size (bytes)
  relativeOffset: number;  // within data region
  offset: number;          // absolute (= dataStart + relativeOffset)
  size: number;
  skip4: number;           // 4-byte field after size (preserved)
  tmp: number;             // used to compute key (preserved)
  key: number;             // per-file entry key
  nameBytes: Uint8Array;   // raw SJIS
  nameStr: string;         // decoded
  pathStr: string;         // full path (dir/name or just name for root)
  // raw decrypted file-entry bytes (indexLength) — for verbatim reuse on repack
  rawEntry: Uint8Array;
  data: Uint8Array | null; // decrypted plaintext (null if not extracted)
}

export interface ParsedArchive {
  header: CpzHeader;
  plugin: Plugin;
  hash: [number, number, number, number];
  dirs: DirInfo[];
  entries: FileEntry[];
  /** decrypted index bytes (dir+file), tableSize long — for verbatim reuse */
  indexPlain: Uint8Array;
}

/** decrypt the whole index using given plugin; throws if structure invalid */
export function parseArchive(buf: Uint8Array, pluginToTry?: Plugin): ParsedArchive {
  const header = readHeader(buf);
  const version = header.version;
  // read encrypted index
  const encIndex = buf.slice(64, 64 + header.tableSize);
  const candidates: Plugin[] = pluginToTry
    ? [pluginToTry]
    : version === 5 ? [plugin5v1(), plugin5v2()] : [plugin6()];

  // bounds-checked readers (throw on out-of-range → triggers plugin fallback)
  const chkU32 = (b: Uint8Array, o: number, max: number): number => {
    if (o < 0 || o + 4 > max) throw new RangeError(`rdU32 oob o=${o} max=${max}`);
    return rdU32(b, o);
  };
  const chkU64 = (b: Uint8Array, o: number, max: number): number => {
    if (o < 0 || o + 8 > max) throw new RangeError(`rdU64 oob o=${o} max=${max}`);
    return rdU64(b, o);
  };
  const chkName = (b: Uint8Array, o: number, max: number): { bytes: Uint8Array; next: number } => {
    if (o < 0 || o >= max) throw new RangeError(`name oob o=${o} max=${max}`);
    let end = o;
    while (end < max && b[end] !== 0) end++;
    if (end >= max) throw new RangeError(`name no terminator o=${o} max=${max}`);
    return { bytes: b.slice(o, end), next: end + 1 };
  };

  let lastErr: unknown = null;
  for (const plugin of candidates) {
    try {
      const hash = getHash(plugin, header.md5Dwords);
      // copy index bytes (we mutate in place)
      const idx = new Uint8Array(encIndex); // dir+file concatenated
      // 1. decrypt_1a on whole index
      crypt1a(idx, plugin, u32(header.mainKey ^ 0x3795b39a), false);
      // split: dir table = idx[0..dirTableSize), file table = idx[dirTableSize..]
      const dirTable = idx.subarray(0, header.dirTableSize);
      const fileTable = idx.subarray(header.dirTableSize);
      // 2. decrypt_2 on dir table (main_key, hash[1], 0x3A)
      crypt2(dirTable, plugin, header.mainKey, hash[1], 0x3a, false);
      // 3. decrypt_1b on dir table
      crypt1b(dirTable, header.mainKey, hash, false);

      // parse dirs (bounds-checked; bad plugin → throws → fallback)
      const dirs: DirInfo[] = [];
      let cursor = 0;
      for (let di = 0; di < header.dirCount; di++) {
        const entryOffset = cursor;
        const indexLength = chkU32(dirTable, cursor, header.dirTableSize); cursor += 4;
        if (indexLength < 16 || entryOffset + indexLength > header.dirTableSize) {
          throw new RangeError(`dir[${di}] bad indexLength=${indexLength} at=${entryOffset} dirTableSize=${header.dirTableSize}`);
        }
        const fileCount = chkU32(dirTable, cursor, header.dirTableSize); cursor += 4;
        const fileTableOffset = chkU32(dirTable, cursor, header.dirTableSize); cursor += 4;
        const fileTableMainKey = chkU32(dirTable, cursor, header.dirTableSize); cursor += 4;
        const name = chkName(dirTable, cursor, header.dirTableSize);
        const rawEntry = dirTable.slice(entryOffset, entryOffset + indexLength);
        dirs.push({
          indexLength, fileCount, fileTableOffset, fileTableMainKey,
          pathBytes: name.bytes, pathStr: decodeSjis(name.bytes),
          fileTableSize: 0, rawEntry,
        });
        cursor = entryOffset + indexLength;
      }
      // compute each dir's fileTableSize from next dir's offset (or remainder)
      for (let di = 0; di < dirs.length; di++) {
        if (di < dirs.length - 1) {
          dirs[di].fileTableSize = dirs[di + 1].fileTableOffset - dirs[di].fileTableOffset;
        } else {
          dirs[di].fileTableSize = header.tableSize - header.dirTableSize - dirs[di].fileTableOffset;
        }
        // validate file-table region fits
        if (dirs[di].fileTableSize < 0 || dirs[di].fileTableOffset < 0
            || dirs[di].fileTableOffset + dirs[di].fileTableSize > header.fileTableSize) {
          throw new RangeError(`dir[${di}] file-table region out of bounds`);
        }
        // sanity: fileCount must fit (each entry ≥ 24 bytes + 1 name byte)
        if (fileCountSane(dirs[di].fileCount, dirs[di].fileTableSize) === false) {
          throw new RangeError(`dir[${di}] fileCount=${dirs[di].fileCount} implausible for fileTableSize=${dirs[di].fileTableSize}`);
        }
      }

      // 4. per dir: decrypt_2 (hash[2], 0x7E) then decrypt_1c (dir key)
      const entries: FileEntry[] = [];
      for (let di = 0; di < dirs.length; di++) {
        const dir = dirs[di];
        const regionStart = header.dirTableSize + dir.fileTableOffset;
        const regionEnd = regionStart + dir.fileTableSize;
        const region = idx.subarray(regionStart, regionEnd);
        crypt2(region, plugin, header.mainKey, hash[2], 0x7e, false);
        crypt1c(region, plugin, dir.fileTableMainKey, hash, false);

        let fc = 0;
        let c = 0;
        while (fc < dir.fileCount && c < region.length) {
          const entryOffset = c;
          const indexLength = chkU32(region, c, region.length); c += 4;
          if (indexLength < 24 || entryOffset + indexLength > region.length) {
            throw new RangeError(`dir[${di}] entry[${fc}] bad indexLength=${indexLength} at=${entryOffset} regionLen=${region.length}`);
          }
          const relativeOffset = chkU64(region, c, region.length); c += 8;
          const size = chkU32(region, c, region.length); c += 4;
          const skip4 = chkU32(region, c, region.length); c += 4;
          const tmp = chkU32(region, c, region.length); c += 4;
          const nm = chkName(region, c, region.length);
          const rawEntry = region.slice(entryOffset, entryOffset + indexLength);
          const key = u32(u32(u32(header.mainKey ^ u32(dir.fileTableMainKey + tmp)) + header.dirCount - 0x5c29e87b) ^ header.extraKey);
          const nameStr = decodeSjis(nm.bytes);
          const pathStr = dir.pathStr !== 'root' ? `${dir.pathStr}/${nameStr}` : nameStr;
          entries.push({
            dirIndex: di, indexLength, relativeOffset,
            offset: header.dataStart + relativeOffset, size, skip4, tmp, key,
            nameBytes: nm.bytes, nameStr, pathStr, rawEntry, data: null,
          });
          c = entryOffset + indexLength;
          fc++;
        }
        // must have parsed exactly fileCount entries
        if (fc !== dir.fileCount) {
          throw new RangeError(`dir[${di}] parsed ${fc} entries but fileCount=${dir.fileCount}`);
        }
      }
      // final validation: every entry's data must fit within the archive buffer
      for (const e of entries) {
        if (e.offset < header.dataStart || e.offset + e.size > buf.length) {
          throw new RangeError(`entry "${e.pathStr}" data out of bounds offset=${e.offset} size=${e.size} bufLen=${buf.length}`);
        }
      }
      return { header, plugin, hash, dirs, entries, indexPlain: idx };
    } catch (e) {
      lastErr = e;
      continue;
    }
  }
  throw new Error(`Failed to parse archive with any known plugin. Last error: ${lastErr}`);
}

/** sanity: fileCount can't exceed what the file-table region can hold (each entry ≥ 24B+1B name) */
function fileCountSane(fileCount: number, fileTableSize: number): boolean {
  if (fileCount > 0x100000) return false; // hard cap (these archives have hundreds, not millions)
  if (fileCount === 0) return true;
  const minPerEntry = 25; // 24 fixed + ≥1 name byte
  return fileCount * minPerEntry <= fileTableSize + 4; // small slack
}

// ----------------------------------------------------------------------------
// Extract file data (decrypt_3)
// ----------------------------------------------------------------------------
export function extractEntry(buf: Uint8Array, arch: ParsedArchive, entry: FileEntry): Uint8Array {
  const data = buf.slice(entry.offset, entry.offset + entry.size);
  crypt3(data, arch.plugin, arch.hash[3], arch.header.mainKey, arch.hash, entry.key, false);
  return data;
}

/** unpack: parse + extract all entries (plaintext data attached) */
export function unpackArchive(buf: Uint8Array): ParsedArchive {
  const arch = parseArchive(buf);
  for (const e of arch.entries) {
    e.data = extractEntry(buf, arch, e);
  }
  return arch;
}

// ----------------------------------------------------------------------------
// Repack: build a new archive from original + replacements
// ----------------------------------------------------------------------------
export function repackArchive(originalBuf: Uint8Array, replacements: Map<string, Uint8Array>): Uint8Array {
  const arch = unpackArchive(originalBuf);
  const { header, plugin, hash, dirs, entries } = arch;

  // 1. Decide each entry's plaintext data (replacement or original)
  const outData: Uint8Array[] = entries.map((e) => {
    const rep = replacements.get(e.pathStr);
    if (rep) return rep;
    if (e.data) return e.data;
    return extractEntry(originalBuf, arch, e);
  });

  // 2. Recompute offsets sequentially from dataStart
  let cursor = header.dataStart;
  const newRel: number[] = [];
  for (let i = 0; i < entries.length; i++) {
    newRel[i] = cursor - header.dataStart;
    cursor += outData[i].length;
  }

  // 3. Patch relative_offset (u64 @ entry raw+4) and size (u32 @ entry raw+12)
  //    in the decrypted index (indexPlain), per entry.
  //    indexPlain layout: [dirTable (dirTableSize)][fileTable (fileTableSize)]
  //    each dir's file table region starts at dirTableSize + dir.fileTableOffset
  const idx = new Uint8Array(arch.indexPlain); // copy of decrypted index
  // For each dir, we need to find its entries' raw entries within idx and patch.
  // Walk dirs again to locate file entries (same parse offsets).
  {
    // re-walk dir entries to get base offsets of each dir's file region
    let dirCursor = 0;
    const dirRegions: { fileTableOffset: number; fileTableSize: number; fileCount: number }[] = [];
    for (let di = 0; di < dirs.length; di++) {
      const indexLength = rdU32(idx, dirCursor);
      const fileCount = rdU32(idx, dirCursor + 4);
      const fileTableOffset = rdU32(idx, dirCursor + 8);
      dirRegions.push({ fileTableOffset, fileTableSize: dirs[di].fileTableSize, fileCount });
      dirCursor += indexLength;
    }
    let entryIdx = 0;
    for (let di = 0; di < dirs.length; di++) {
      const r = dirRegions[di];
      let c = header.dirTableSize + r.fileTableOffset;
      for (let f = 0; f < r.fileCount; f++) {
        const entryOffset = c;
        const indexLength = rdU32(idx, c); c += 4;
        c += 8; // skip relative_offset (we patch below)
        c += 4; // skip size (patch below)
        c += 4; // skip4
        c += 4; // tmp
        // name + padding skipped
        // patch relativeOffset (u64 at entryOffset+4) and size (u32 at entryOffset+12)
        wrU64(idx, entryOffset + 4, newRel[entryIdx]);
        wrU32(idx, entryOffset + 12, outData[entryIdx].length);
        c = entryOffset + indexLength;
        entryIdx++;
      }
    }
  }

  // 4. Re-encrypt index (reverse of decryption order):
  //    a. per dir: crypt1c(encode) then crypt2(hash[2],0x7E)(encode) on file region
  //    b. crypt1b(encode) then crypt2(hash[1],0x3A)(encode) on dir table region
  //    c. crypt1a(encode) on whole index
  // NOTE: crypt2/crypt1c/crypt1b/crypt1a all operate in place on idx.
  // (a) per dir file regions
  for (let di = 0; di < dirs.length; di++) {
    const region = idx.subarray(header.dirTableSize + dirs[di].fileTableOffset,
      header.dirTableSize + dirs[di].fileTableOffset + dirs[di].fileTableSize);
    crypt1c(region, plugin, dirs[di].fileTableMainKey, hash, true);
    crypt2(region, plugin, header.mainKey, hash[2], 0x7e, true);
  }
  // (b) dir table region
  const dirTableRegion = idx.subarray(0, header.dirTableSize);
  crypt1b(dirTableRegion, header.mainKey, hash, true);
  crypt2(dirTableRegion, plugin, header.mainKey, hash[1], 0x3a, true);
  // (c) whole index
  crypt1a(idx, plugin, u32(header.mainKey ^ 0x3795b39a), true);

  // 5. Re-encrypt each file's data (crypt3 encode)
  const encData: Uint8Array[] = outData.map((d, i) => {
    const enc = new Uint8Array(d);
    crypt3(enc, plugin, hash[3], header.mainKey, hash, entries[i].key, true);
    return enc;
  });

  // 6. Assemble: header(64) + encIndex + encData...
  //    header: reuse original 64 bytes verbatim (dirTableSize/fileTableSize unchanged)
  const totalLen = 64 + idx.length + encData.reduce((s, d) => s + d.length, 0);
  const out = new Uint8Array(totalLen);
  out.set(header.raw, 0);
  out.set(idx, 64);
  let w = 64 + idx.length;
  for (const d of encData) { out.set(d, w); w += d.length; }
  return out;
}

// ----------------------------------------------------------------------------
// Round-trip verification: unpack(original) -> repack(no replacements) == original?
// ----------------------------------------------------------------------------
export function roundtripVerify(originalBuf: Uint8Array): { ok: boolean; firstDiff: number | null; message: string } {
  const repacked = repackArchive(originalBuf, new Map());
  if (repacked.length !== originalBuf.length) {
    const min = Math.min(repacked.length, originalBuf.length);
    for (let i = 0; i < min; i++) {
      if (repacked[i] !== originalBuf[i]) {
        return { ok: false, firstDiff: i, message: `length differs (orig=${originalBuf.length} repacked=${repacked.length}); first byte diff at ${i}` };
      }
    }
    return { ok: false, firstDiff: min, message: `length differs (orig=${originalBuf.length} repacked=${repacked.length}); identical up to ${min}` };
  }
  for (let i = 0; i < originalBuf.length; i++) {
    if (repacked[i] !== originalBuf[i]) {
      return { ok: false, firstDiff: i, message: `byte diff at offset ${i} (0x${i.toString(16)}): orig=0x${originalBuf[i].toString(16)} repacked=0x${repacked[i].toString(16)}` };
    }
  }
  return { ok: true, firstDiff: null, message: 'round-trip byte-exact ✓' };
}

// ----------------------------------------------------------------------------
// List (metadata only, no file extraction)
// ----------------------------------------------------------------------------
export interface ListResult {
  version: number;
  plugin: string;
  dirCount: number;
  dirs: { path: string; fileCount: number }[];
  entries: { path: string; size: number }[];
  totalFiles: number;
  totalUncompressed: number;
}
export function listArchive(buf: Uint8Array): ListResult {
  const arch = parseArchive(buf);
  let totalUncompressed = 0;
  return {
    version: arch.header.version,
    plugin: arch.plugin.name,
    dirCount: arch.dirs.length,
    dirs: arch.dirs.map((d) => ({ path: d.pathStr, fileCount: d.fileCount })),
    entries: arch.entries.map((e) => { totalUncompressed += e.size; return { path: e.pathStr, size: e.size }; }),
    totalFiles: arch.entries.length,
    totalUncompressed,
  };
}
