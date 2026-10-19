/**
 * selftest.ts — validates the core cpz5 library.
 *  1. MD5 (standard IV) against node:crypto — proves the MD5 core is correct.
 *  2. Build a synthetic CPZ5 archive with the encoder, then parse+extract+roundtrip.
 *
 * Run: bun run src/selftest.ts
 */
import * as crypto from 'node:crypto';
import {
  plugin5v1, plugin6, getHash, md5CustomIV,
  parseArchive, unpackArchive, extractEntry, repackArchive, roundtripVerify,
  crypt1a, crypt1b, crypt1c, crypt2, crypt3,
  rdU32, wrU32, wrU64, u32,
  type Plugin,
} from './cpz5';

let pass = 0, fail = 0;
const check = (name: string, cond: boolean, extra = '') => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name} ${extra}`); }
};
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

// ---------------------------------------------------------------------------
// 1. MD5 standard-IV validation against node:crypto
// ---------------------------------------------------------------------------
console.log('\n[1] MD5 standard-IV vs node:crypto');
const STD_IV: [number, number, number, number] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
for (const msg of ['', 'abc', 'The quick brown fox jumps over the lazy dog', 'a'.repeat(100)]) {
  const mine = toHex(md5CustomIV(Buffer.from(msg, 'utf8'), STD_IV));
  const ref = crypto.createHash('md5').update(msg, 'utf8').digest('hex');
  check(`md5(${JSON.stringify(msg).slice(0, 30)})`, mine === ref, `\n  mine=${mine}\n  ref =${ref}`);
}

// ---------------------------------------------------------------------------
// 2. Synthetic CPZ5 archive: build with encoder, then decode/extract/roundtrip
// ---------------------------------------------------------------------------
console.log('\n[2] Synthetic CPZ5 round-trip');

// Pick plugin 5v1 and known keys.
const plugin = plugin5v1();
const version: 5 | 6 = 5;
const mainKey = 0x12345678;
const dirCount = 1;
// md5 dwords (arbitrary, used to derive hash)
const md5Dwords: [number, number, number, number] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
const hash = getHash(plugin, md5Dwords);
const dirKey = 0xdeadbeef; // file_table_main_key

// Build two files in "root" dir
const fileA = Buffer.from('Hello CPZ5 world — file A payload!', 'utf8');
const fileB = new Uint8Array(1000);
for (let i = 0; i < fileB.length; i++) fileB[i] = (i * 7 + 3) & 0xff;

// file entry layout: [entry_size:4][rel_offset:8][size:4][skip4:4][tmp:4][name+null+pad]
function buildFileEntry(name: string, relOffset: number, size: number, tmp: number): { bytes: Uint8Array; entrySize: number } {
  const nameBytes = Buffer.from(name, 'utf8');
  const fixed = 4 + 8 + 4 + 4 + 4; // 24
  const minLen = fixed + nameBytes.length + 1;
  // pad to multiple of 4
  let entrySize = minLen;
  while (entrySize % 4 !== 0) entrySize++;
  const buf = new Uint8Array(entrySize);
  wrU32(buf, 0, entrySize);
  wrU64(buf, 4, relOffset);
  wrU32(buf, 12, size);
  wrU32(buf, 16, 0); // skip4
  wrU32(buf, 20, tmp);
  buf.set(nameBytes, 24);
  // null terminator + padding (zero) already
  return { bytes: buf, entrySize };
}
function buildDirEntry(name: string, fileCount: number, fileTableOffset: number, dirKeyVal: number): Uint8Array {
  const nameBytes = Buffer.from(name, 'utf8');
  const fixed = 4 + 4 + 4 + 4; // 16
  let entrySize = fixed + nameBytes.length + 1;
  while (entrySize % 4 !== 0) entrySize++;
  const buf = new Uint8Array(entrySize);
  wrU32(buf, 0, entrySize);
  wrU32(buf, 4, fileCount);
  wrU32(buf, 8, fileTableOffset);
  wrU32(buf, 12, dirKeyVal);
  buf.set(nameBytes, 16);
  return buf;
}

const entryA = buildFileEntry('image_a.pb3', 0, fileA.length, 0xaaaa);
const entryB = buildFileEntry('image_b.pb3', fileA.length, fileB.length, 0xbbbb);
const dirEntry = buildDirEntry('root', 2, 0, dirKey);

const dirTableSize = dirEntry.length;
const fileTableSize = entryA.bytes.length + entryB.bytes.length;
const tableSize = dirTableSize + fileTableSize;
const dataStart = 64 + tableSize;

// assemble plaintext index
const indexPlain = new Uint8Array(tableSize);
indexPlain.set(dirEntry, 0);
indexPlain.set(entryA.bytes, dirTableSize);
indexPlain.set(entryB.bytes, dirTableSize + entryA.bytes.length);

// Encrypt index using the SAME sequence as repackArchive:
//  (a) per dir: crypt1c(encode) then crypt2(hash[2],0x7E)(encode)
//  (b) crypt1b(encode) then crypt2(hash[1],0x3A)(encode) on dir table
//  (c) crypt1a(encode) on whole index
const idx = new Uint8Array(indexPlain);
// (a) file region for root dir (offset 0 within file table, size fileTableSize)
const fileRegion = idx.subarray(dirTableSize, dirTableSize + fileTableSize);
crypt1c(fileRegion, plugin, dirKey, hash, true);
crypt2(fileRegion, plugin, mainKey, hash[2], 0x7e, true);
// (b) dir table region
const dirRegion = idx.subarray(0, dirTableSize);
crypt1b(dirRegion, mainKey, hash, true);
crypt2(dirRegion, plugin, mainKey, hash[1], 0x3a, true);
// (c) whole
crypt1a(idx, plugin, u32(mainKey ^ 0x3795b39a), true);

// Build file data: encrypt with crypt3. entry key formula:
//   key = ((mainKey ^ (dirKey + tmp)) + dirCount - 0x5C29E87B) ^ extraKey ; extraKey=0 for v5
const keyA = u32(u32(u32(mainKey ^ u32(dirKey + 0xaaaa)) + dirCount - 0x5c29e87b) ^ 0);
const keyB = u32(u32(u32(mainKey ^ u32(dirKey + 0xbbbb)) + dirCount - 0x5c29e87b) ^ 0);
const encA = new Uint8Array(fileA); crypt3(encA, plugin, hash[3], mainKey, hash, keyA, true);
const encB = new Uint8Array(fileB); crypt3(encB, plugin, hash[3], mainKey, hash, keyB, true);

// Build header (64 bytes). v5 layout with XOR encoding.
const HEADER_XOR_V5 = {
  dirCount: 0xfe3a53d9, dirTableSize: 0x37f298e7, fileTableSize: 0x7a6f3a2c,
  md5: [0x43de7c19, 0xcc65f415, 0xd016a93c, 0x97a3ba9a], mainKey: 0xae7d39bf,
};
const header = new Uint8Array(64);
Buffer.from('CPZ5', 'latin1').forEach((b, i) => (header[i] = b));
wrU32(header, 4, u32(dirCount ^ HEADER_XOR_V5.dirCount));
wrU32(header, 8, u32(dirTableSize ^ HEADER_XOR_V5.dirTableSize));
wrU32(header, 12, u32(fileTableSize ^ HEADER_XOR_V5.fileTableSize));
// skip 16 bytes (16..31) — leave zero
wrU32(header, 32, u32(md5Dwords[0] ^ HEADER_XOR_V5.md5[0]));
wrU32(header, 36, u32(md5Dwords[1] ^ HEADER_XOR_V5.md5[1]));
wrU32(header, 40, u32(md5Dwords[2] ^ HEADER_XOR_V5.md5[2]));
wrU32(header, 44, u32(md5Dwords[3] ^ HEADER_XOR_V5.md5[3]));
wrU32(header, 48, u32(mainKey ^ HEADER_XOR_V5.mainKey));
// skip 12 bytes (52..63) — leave zero (extra_key region for v5)

// Assemble full archive
const total = 64 + idx.length + encA.length + encB.length;
const archive = new Uint8Array(total);
archive.set(header, 0);
archive.set(idx, 64);
archive.set(encA, 64 + idx.length);
archive.set(encB, 64 + idx.length + encA.length);

// --- 2a. parseArchive ---
console.log('\n  [2a] parseArchive');
let arch: ReturnType<typeof parseArchive>;
try {
  arch = parseArchive(archive);
  check('parses without throwing', true);
} catch (e) {
  arch = null as never;
  check('parses without throwing', false, String(e));
}
if (arch) {
  check('version === 5', arch.header.version === 5);
  check('plugin === 5v1', arch.plugin.name === '5v1');
  check('dirCount === 1', arch.header.dirCount === 1);
  check('2 entries parsed', arch.entries.length === 2, `got ${arch.entries.length}`);
  check('entry A path', arch.entries[0]?.pathStr === 'image_a.pb3', arch.entries[0]?.pathStr);
  check('entry B path', arch.entries[1]?.pathStr === 'image_b.pb3', arch.entries[1]?.pathStr);
  check('entry A size', arch.entries[0]?.size === fileA.length, `${arch.entries[0]?.size}`);
  check('entry B size', arch.entries[1]?.size === fileB.length, `${arch.entries[1]?.size}`);
  check('entry A key matches', arch.entries[0]?.key === keyA, `${arch.entries[0]?.key?.toString(16)} vs ${keyA.toString(16)}`);
  check('entry B key matches', arch.entries[1]?.key === keyB, `${arch.entries[1]?.key?.toString(16)} vs ${keyB.toString(16)}`);
}

// --- 2b. extractEntry ---
console.log('\n  [2b] extractEntry (data decryption)');
if (arch) {
  const da = extractEntry(archive, arch, arch.entries[0]);
  const db = extractEntry(archive, arch, arch.entries[1]);
  check('file A decrypts to original', toHex(da) === toHex(fileA));
  check('file B decrypts to original', toHex(db) === toHex(fileB));
}

// --- 2c. full round-trip (unpack then repack with no replacements) ---
console.log('\n  [2c] roundtripVerify (byte-exact)');
const rt = roundtripVerify(archive);
check('round-trip byte-exact', rt.ok, rt.message);

// --- 2d. repack with a replacement (size change) ---
console.log('\n  [2d] repack with replacement (size change)');
if (arch) {
  const newA = Buffer.from('REPLACED FILE A — much longer payload to force offset shift!!!', 'utf8');
  const reps = new Map<string, Uint8Array>([['image_a.pb3', newA]]);
  const repacked = repackArchive(archive, reps);
  // re-parse the repacked archive and verify
  const arch2 = parseArchive(repacked);
  check('repacked parses', true);
  check('repacked entry A size updated', arch2.entries[0].size === newA.length, `${arch2.entries[0].size}`);
  check('repacked entry B offset shifted', arch2.entries[1].offset === arch2.entries[0].offset + newA.length,
    `${arch2.entries[1].offset} vs ${arch2.entries[0].offset + newA.length}`);
  const da2 = extractEntry(repacked, arch2, arch2.entries[0]);
  const db2 = extractEntry(repacked, arch2, arch2.entries[1]);
  check('repacked A decrypts to REPLACED', toHex(da2) === toHex(newA));
  check('repacked B decrypts to original B', toHex(db2) === toHex(fileB));
  // and a second round-trip on the repacked archive (stability)
  check('repacked archive itself round-trips', roundtripVerify(repacked).ok, roundtripVerify(repacked).message);
}

// --- 2e. v6 plugin sanity (build + roundtrip) ---
console.log('\n  [2e] CPZ6 plugin round-trip');
{
  const p6 = plugin6();
  const mk = 0x0badf00d;
  const md5d: [number, number, number, number] = [0x55, 0x66, 0x77, 0x88];
  const h6 = getHash(p6, md5d);
  const dk = 0xcafebabe;
  const tmpF = 0x9999;
  const extraKey = u32(u32(rotr32(u32(0x37acf832 ^ 0x37acf832), 5) * 0x7da8f173) + 0x13712765); // tmp2=0
  // Simplified: build a 1-dir/1-file v6 archive by reusing repack machinery is complex;
  // instead just test that crypt3 encode/decode are inverses for plugin6 with v6 keys.
  const fkey = u32(u32(u32(mk ^ u32(dk + tmpF)) + 1 - 0x5c29e87b) ^ extraKey);
  const orig = new Uint8Array(500);
  for (let i = 0; i < orig.length; i++) orig[i] = (i * 13 + 5) & 0xff;
  const enc = new Uint8Array(orig); crypt3(enc, p6, h6[3], mk, h6, fkey, true);
  const dec = new Uint8Array(enc); crypt3(dec, p6, h6[3], mk, h6, fkey, false);
  check('v6 crypt3 encode/decode inverse', toHex(dec) === toHex(orig));
}

function rotr32(x: number, n: number): number { return ((x >>> n) | (x << (32 - n))) >>> 0; }

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
if (fail > 0) process.exit(1);
