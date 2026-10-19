#!/usr/bin/env bun
/**
 * cli.ts — Standalone PC CLI for packing/unpacking .cpz5 game archives
 * (Purple Software / happymaher regret end).
 *
 * Commands:
 *   cpz5-pack list      <file.cpz5>
 *   cpz5-pack unpack    <file.cpz5> <outDir>
 *   cpz5-pack repack    <original.cpz5> <inDir> <out.cpz5>
 *   cpz5-pack roundtrip <file.cpz5>
 *   cpz5-pack help
 *
 * The core crypto is in ./cpz5.ts (final, validated). This file is a thin
 * filesystem/UX wrapper around it.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  unpackArchive,
  repackArchive,
  roundtripVerify,
  listArchive,
} from './cpz5';
import { decodePb3, pb3Info } from './pb3';
import { encodePng } from './pngenc';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const die = (msg: string, code = 1): never => {
  console.error(`error: ${msg}`);
  process.exit(code);
};

/** read a file as Uint8Array (Buffer is a Uint8Array; cast for typing) */
function readBytes(p: string): Uint8Array {
  const b = fs.readFileSync(p);
  return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}
function writeBytes(p: string, data: Uint8Array): void {
  fs.writeFileSync(p, Buffer.from(data.buffer, data.byteOffset, data.byteLength));
}

/** recursively walk a directory; yield paths relative to `root` using '/' */
function* walkRel(root: string): Generator<string> {
  const stack: string[] = [''];
  while (stack.length) {
    const rel = stack.pop()!;
    const abs = path.join(root, rel);
    const st = fs.statSync(abs);
    if (st.isDirectory()) {
      for (const name of fs.readdirSync(abs)) {
        const childRel = rel ? `${rel}/${name}` : name;
        stack.push(childRel);
      }
    } else if (st.isFile()) {
      yield rel;
    }
  }
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------
function cmdList(file: string): void {
  const buf = readBytes(file);
  const info = listArchive(buf);
  console.log(`file:        ${file}`);
  console.log(`version:     CPZ${info.version}`);
  console.log(`plugin:      ${info.plugin}`);
  console.log(`dirs:        ${info.dirCount}`);
  console.log(`files:       ${info.totalFiles}`);
  console.log(`uncompressed:${formatBytes(info.totalUncompressed)} (${info.totalUncompressed} B)`);
  console.log('');
  console.log('Directories:');
  for (const d of info.dirs) {
    console.log(`  ${d.path === '' ? '(root)' : d.path}  —  ${d.fileCount} file${d.fileCount === 1 ? '' : 's'}`);
  }
  console.log('');
  console.log('Entries:');
  // tree by directory
  const byDir = new Map<string, { path: string; size: number }[]>();
  for (const e of info.entries) {
    const dir = e.path.includes('/') ? e.path.slice(0, e.path.lastIndexOf('/')) : '';
    if (!byDir.has(dir)) byDir.set(dir, []);
    byDir.get(dir)!.push(e);
  }
  for (const [dir, entries] of byDir) {
    console.log(`  ${dir === '' ? '(root)' : dir}/`);
    for (const e of entries) {
      const name = e.path.includes('/') ? e.path.slice(e.path.lastIndexOf('/') + 1) : e.path;
      console.log(`    ${name}  (${formatBytes(e.size)})`);
    }
  }
}

function cmdUnpack(file: string, outDir: string): void {
  const buf = readBytes(file);
  const arch = unpackArchive(buf);
  fs.mkdirSync(outDir, { recursive: true });
  const manifestEntries: { path: string; size: number }[] = [];
  let totalBytes = 0;
  for (const e of arch.entries) {
    if (!e.data) throw new Error(`internal: entry ${e.pathStr} has no data`);
    const outPath = path.join(outDir, ...e.pathStr.split('/'));
    const fileDir = path.dirname(outPath);
    if (fileDir && fileDir !== '.' && fileDir !== '') {
      fs.mkdirSync(fileDir, { recursive: true });
    }
    writeBytes(outPath, e.data);
    manifestEntries.push({ path: e.pathStr, size: e.data.length });
    totalBytes += e.data.length;
  }
  const manifest = {
    version: arch.header.version,
    plugin: arch.plugin.name,
    originalArchive: path.basename(file),
    entries: manifestEntries,
  };
  writeBytes(path.join(outDir, 'manifest.json'), new TextEncoder().encode(JSON.stringify(manifest, null, 2) + '\n'));
  console.log(`extracted ${manifestEntries.length} file${manifestEntries.length === 1 ? '' : 's'} (${formatBytes(totalBytes)}) to ${outDir}`);
  console.log(`manifest written to ${path.join(outDir, 'manifest.json')}`);
}

function cmdRepack(originalFile: string, inDir: string, outFile: string): void {
  const origBuf = readBytes(originalFile);
  // unpack original so we know each entry's original plaintext bytes (lets us
  // count how many files were actually MODIFIED vs just present in inDir).
  const arch = unpackArchive(origBuf);
  const origDataByPath = new Map<string, Uint8Array>();
  for (const e of arch.entries) {
    if (e.data) origDataByPath.set(e.pathStr, e.data);
  }
  const knownPaths = new Set(arch.entries.map((e) => e.pathStr));
  // walk inDir, build replacement map
  const replacements = new Map<string, Uint8Array>();
  const ignored: string[] = [];
  let modifiedCount = 0;
  for (const rel of walkRel(inDir)) {
    // normalize: use forward slashes; skip manifest.json at root
    const pathStr = rel.split(path.sep).join('/');
    if (pathStr === 'manifest.json') continue;
    if (!knownPaths.has(pathStr)) {
      ignored.push(pathStr);
      continue;
    }
    const abs = path.join(inDir, ...rel.split('/'));
    const newData = readBytes(abs);
    replacements.set(pathStr, newData);
    // count as "modified" only if bytes actually differ from the original
    const orig = origDataByPath.get(pathStr);
    if (!orig || orig.length !== newData.length || !orig.every((b, i) => b === newData[i])) {
      modifiedCount++;
    }
  }
  if (ignored.length > 0) {
    console.warn(`warning: ${ignored.length} file(s) in ${inDir} do not match any archive entry (ignored):`);
    for (const p of ignored) console.warn(`  - ${p}`);
  }
  const result = repackArchive(origBuf, replacements);
  const outDir = path.dirname(outFile);
  if (outDir && outDir !== '.' && outDir !== '') {
    fs.mkdirSync(outDir, { recursive: true });
  }
  writeBytes(outFile, result);
  const total = arch.entries.length;
  console.log(`repacked ${modifiedCount}/${total} file(s) modified (${replacements.size} present in ${inDir})`);
  console.log(`original: ${originalFile} (${formatBytes(origBuf.length)})`);
  console.log(`output:   ${outFile} (${formatBytes(result.length)})`);
}

function cmdRoundtrip(file: string): void {
  const buf = readBytes(file);
  const r = roundtripVerify(buf);
  if (r.ok) {
    console.log(`OK: ${r.message}`);
    console.log(`file: ${file} (${formatBytes(buf.length)})`);
    console.log('unpack → repack(no replacements) is byte-exact with the original.');
    console.log('This proves the tool is correct for THIS specific file — safe to repack.');
  } else {
    console.log(`FAIL: ${r.message}`);
    if (r.firstDiff !== null) console.log(`first diff at offset ${r.firstDiff} (0x${r.firstDiff.toString(16)})`);
    console.log(`file: ${file} (${formatBytes(buf.length)})`);
    console.log('DO NOT use repack on this file — the tool may produce an incompatible archive.');
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// pb3 ↔ png batch conversion
// ---------------------------------------------------------------------------
function cmdPb3ToPng(folder: string): void {
  const absFolder = path.resolve(folder);
  if (!fs.existsSync(absFolder) || !fs.statSync(absFolder).isDirectory()) {
    die(`not a directory: ${absFolder}`);
  }
  let ok = 0, fail = 0;
  const failures: { file: string; error: string }[] = [];
  for (const rel of walkRel(absFolder)) {
    if (!rel.toLowerCase().endsWith('.pb3')) continue;
    const absPb3 = path.join(absFolder, ...rel.split('/'));
    const absPng = absPb3.slice(0, -4) + '.png';
    try {
      const data = readBytes(absPb3);
      const img = decodePb3(data, path.dirname(absPb3));
      const png = encodePng(img.width, img.height, img.rgba);
      writeBytes(absPng, png);
      ok++;
      console.log(`  ✓ ${rel} → ${rel.slice(0, -4)}.png (${img.width}×${img.height})`);
    } catch (e) {
      fail++;
      const msg = e instanceof Error ? e.message : String(e);
      failures.push({ file: rel, error: msg });
      console.log(`  ✗ ${rel} — ${msg}`);
    }
  }
  console.log('');
  console.log(`pb3→png: ${ok} converted, ${fail} failed`);
  if (failures.length > 0 && fail <= 10) {
    console.log('failures:');
    for (const f of failures) console.log(`  ${f.file}: ${f.error}`);
  }
}

function cmdPngToPb3(folder: string): void {
  const absFolder = path.resolve(folder);
  if (!fs.existsSync(absFolder) || !fs.statSync(absFolder).isDirectory()) {
    die(`not a directory: ${absFolder}`);
  }
  let count = 0;
  for (const rel of walkRel(absFolder)) {
    if (!rel.toLowerCase().endsWith('.png')) continue;
    const absPng = path.join(absFolder, ...rel.split('/'));
    const absPb3 = absPng.slice(0, -4) + '.pb3';
    // The game engine accepts raw PNG data in .pb3 slots (dual loader).
    // So we just copy the PNG bytes with .pb3 extension.
    const data = readBytes(absPng);
    writeBytes(absPb3, data);
    count++;
    console.log(`  ✓ ${rel} → ${rel.slice(0, -4)}.pb3`);
  }
  console.log('');
  console.log(`png→pb3: ${count} file(s) converted (PNG data renamed to .pb3 — engine accepts it)`);
  if (count > 0) {
    console.log('note: the .pb3 files now contain raw PNG data. The game engine loads them.');
    console.log('      You can now run: cpz5-pack repack <original.cpz5> <folder> <output.cpz5>');
  }
}

function cmdPb3Info(file: string): void {
  const data = readBytes(file);
  try {
    const info = pb3Info(data);
    console.log(`file:      ${file}`);
    console.log(`main_type: ${info.mainType}`);
    console.log(`sub_type:  0x${info.subType.toString(16)}`);
    console.log(`width:     ${info.width}`);
    console.log(`height:    ${info.height}`);
    console.log(`depth:     ${info.depth} (${info.depth >> 3} channels)`);
    const typeNames: Record<number, string> = { 1: 'v1 (LZSS blocks)', 2: 'v2 (jbp1+mask)', 3: 'v3 (jbp1)', 5: 'v5 (LZSS+delta)', 6: 'v6 (overlay)' };
    console.log(`variant:   ${typeNames[info.mainType] || 'unknown'}`);
  } catch (e) {
    die(e instanceof Error ? e.message : String(e));
  }
}

// ---------------------------------------------------------------------------
// Universal one-shot commands: extract-all / build-all
// ---------------------------------------------------------------------------

/** extract-all: unpack .cpz → folder, then .pb3 → .png, delete decoded .pb3 */
function cmdExtractAll(cpzFile: string, outDir: string): void {
  console.log('=== Шаг 1: распаковка архива ===');
  cmdUnpack(cpzFile, outDir);
  console.log('');
  console.log('=== Шаг 2: конвертация .pb3 → .png ===');
  const absFolder = path.resolve(outDir);
  let ok = 0, fail = 0, deleted = 0;
  const failures: { file: string; error: string }[] = [];
  for (const rel of walkRel(absFolder)) {
    if (!rel.toLowerCase().endsWith('.pb3')) continue;
    const absPb3 = path.join(absFolder, ...rel.split('/'));
    const absPng = absPb3.slice(0, -4) + '.png';
    try {
      const data = readBytes(absPb3);
      const img = decodePb3(data, path.dirname(absPb3));
      const png = encodePng(img.width, img.height, img.rgba);
      writeBytes(absPng, png);
      ok++;
      console.log(`  ✓ ${rel} → ${rel.slice(0, -4)}.png (${img.width}×${img.height})`);
      // delete the .pb3 (decode succeeded)
      fs.unlinkSync(absPb3);
      deleted++;
    } catch (e) {
      fail++;
      const msg = e instanceof Error ? e.message : String(e);
      failures.push({ file: rel, error: msg });
      console.log(`  ✗ ${rel} — ${msg} (файл сохранён)`);
    }
  }
  console.log('');
  console.log(`pb3→png: ${ok} сконвертировано, ${fail} не удалось (сохранены как .pb3)`);
  console.log(`удалено .pb3: ${deleted}`);
  if (failures.length > 0 && fail <= 20) {
    console.log('не сконвертированы (остались .pb3, будут запакованы как есть):');
    for (const f of failures) console.log(`  ${f.file}: ${f.error}`);
  }
  console.log('');
  console.log('Готово! Папка содержит:');
  console.log('  - .png файлы (можно редактировать в любом редакторе)');
  console.log('  - .pb3 файлы, которые не удалось декодировать (оставлены как есть)');
  console.log('  - manifest.json (список файлов архива)');
  console.log('  - прочие файлы (.ogg, скрипты и т.д.)');
  console.log('');
  console.log(`Для обратной сборки: cpz5-pack build-all ${cpzFile} ${outDir} <result.cpz>`);
}

/** build-all: .png → .pb3, delete converted .png, then repack folder → .cpz */
function cmdBuildAll(originalCpz: string, inDir: string, outCpz: string): void {
  console.log('=== Шаг 1: конвертация .png → .pb3 ===');
  const absFolder = path.resolve(inDir);
  let pngCount = 0, pngDeleted = 0;
  for (const rel of walkRel(absFolder)) {
    if (!rel.toLowerCase().endsWith('.png')) continue;
    const absPng = path.join(absFolder, ...rel.split('/'));
    const absPb3 = absPng.slice(0, -4) + '.pb3';
    // copy PNG bytes to .pb3 (engine accepts raw PNG in .pb3 slots)
    const data = readBytes(absPng);
    writeBytes(absPb3, data);
    pngCount++;
    console.log(`  ✓ ${rel} → ${rel.slice(0, -4)}.pb3`);
    // delete the .png
    fs.unlinkSync(absPng);
    pngDeleted++;
  }
  console.log('');
  console.log(`png→pb3: ${pngCount} сконвертировано, ${pngDeleted} .png удалено`);
  console.log('');
  console.log('=== Шаг 2: запаковка папки → .cpz ===');
  cmdRepack(originalCpz, inDir, outCpz);
  console.log('');
  console.log('Готово! Результат:');
  console.log(`  ${outCpz} — собранный архив`);
  console.log('  Папка теперь содержит только .pb3 и прочие файлы (.ogg, скрипты и т.д.)');
  console.log('  Замените оригинальный .cpz в папке игры на новый и проверьте.');
}

function cmdPb3Info_wrapper(file: string): void { cmdPb3Info(file); }

function cmdHelp(): void {
  console.log(`cpz5-pack — упаковщик/распаковщик архивов .cpz5
(Purple Software / happymaher regret end)

ИСПОЛЬЗОВАНИЕ:
  cpz5-pack <команда> [аргументы]

КОМАНДЫ:
  list <файл.cpz5>
      Показать содержимое архива: версию, плагин, число директорий,
      дерево всех файлов (путь + размер).

  unpack <файл.cpz5> <выходная_папка>
      Распаковать ВСЕ файлы (расшифровать) в указанную папку, сохраняя
      структуру директорий. Также создаёт manifest.json со списком файлов.

  repack <оригинал.cpz5> <входная_папка> <результат.cpz5>
      Запаковать изменённые файлы обратно в .cpz5. Входная папка — это
      та, что получена от unpack (manifest.json игнорируется). Файлы,
      отсутствующие в папке, остаются неизменными (берутся из оригинала).
      Файлы в папке, не matching ни одной записи архива, игнорируются
      с предупреждением.

  roundtrip <файл.cpz5>
      Самотест: распаковать → запаковать (без замен) → побайтово сравнить
      с оригиналом. Рекомендуется запустить ПЕРЕД редактированием, чтобы
      убедиться, что инструмент корректно работает с вашим архивом.

  pb3topng <папка>
      Пакетно конвертировать все .pb3 в папке (рекурсивно) в .png.
      PNG-файлы создаются рядом с .pb3 (то же имя, расширение .png).
      .pb3 файлы не удаляются. Поддерживаются все подверсии PB3 (v1-v6).

  pngtopb3 <папка>
      Пакетно конвертировать все .png в папке (рекурсивно) в .pb3.
      Движок игры принимает сырые PNG-данные в слотах .pb3 (двойной
      загрузчик), поэтому .png просто копируется с расширением .pb3.
      Существующие .pb3 перезаписываются.

  pb3info <файл.pb3>
      Показать информацию о .pb3 файле: тип, размеры, глубину цвета.

  extract-all <файл.cpz> <выходная_папка>
      Универсальная команда распаковки — за один вызов:
        1) распаковывает .cpz в папку (как unpack)
        2) конвертирует все .pb3 → .png (как pb3topng)
        3) удаляет .pb3, которые успешно декодированы
      .pb3, которые не удалось декодировать, остаются в папке.
      После этого можно редактировать .png в любом редакторе.

  build-all <оригинал.cpz> <папка> <результат.cpz>
      Универсальная команда сборки — за один вызов:
        1) конвертирует все .png → .pb3 (как pngtopb3)
        2) удаляет .png, которые успешно сконвертированы
        3) запаковывает папку в .cpz (как repack)
      Папка должна быть получена от extract-all (после редактирования .png).

  help
      Показать эту справку.

ПРИМЕРЫ (полный цикл замены картинок — универсальные команды):
  cpz5-pack roundtrip game.cpz5                        # проверка инструмента
  cpz5-pack extract-all game.cpz5 out\                 # распаковка + .pb3→.png
  # отредактируйте out\image.png в любом редакторе
  cpz5-pack build-all game.cpz5 out\ game.new.cpz5     # .png→.pb3 + запаковка

ПРИМЕРЫ (полный цикл замены картинок — по шагам):
  cpz5-pack roundtrip game.cpz5                        # проверка
  cpz5-pack unpack game.cpz5 out\                      # распаковка архива
  cpz5-pack pb3topng out\                              # .pb3 → .png
  # отредактируйте out\image.png
  cpz5-pack pngtopb3 out\                              # .png → .pb3
  cpz5-pack repack game.cpz5 out\ game.new.cpz5        # запаковка обратно

ПРИМЕРЫ (только звук/данные без конвертации):
  cpz5-pack unpack game.cpz5 out\
  cpz5-pack repack game.cpz5 out\ game.new.cpz5

ЗАПУСК:
  bun run src/cli.ts <команда>          # через bun (см. https://bun.sh)
  cpz5-pack.exe <команда>               # готовый Windows .exe — без зависимостей

Подробнее — в README.md.`);
}

// ---------------------------------------------------------------------------
// arg parsing / dispatch
// ---------------------------------------------------------------------------
function main(argv: string[]): void {
  const args = argv.slice(2); // drop node/bun + script path
  const cmd = args[0];
  try {
    switch (cmd) {
      case 'list': {
        if (args.length !== 2) die('usage: cpz5-pack list <file.cpz5>');
        cmdList(args[1]);
        break;
      }
      case 'unpack': {
        if (args.length !== 3) die('usage: cpz5-pack unpack <file.cpz5> <outDir>');
        cmdUnpack(args[1], args[2]);
        break;
      }
      case 'repack': {
        if (args.length !== 4) die('usage: cpz5-pack repack <original.cpz5> <inDir> <out.cpz5>');
        cmdRepack(args[1], args[2], args[3]);
        break;
      }
      case 'roundtrip': {
        if (args.length !== 2) die('usage: cpz5-pack roundtrip <file.cpz5>');
        cmdRoundtrip(args[1]);
        break;
      }
      case 'pb3topng': {
        if (args.length !== 2) die('usage: cpz5-pack pb3topng <folder>');
        cmdPb3ToPng(args[1]);
        break;
      }
      case 'pngtopb3': {
        if (args.length !== 2) die('usage: cpz5-pack pngtopb3 <folder>');
        cmdPngToPb3(args[1]);
        break;
      }
      case 'pb3info': {
        if (args.length !== 2) die('usage: cpz5-pack pb3info <file.pb3>');
        cmdPb3Info(args[1]);
        break;
      }
      case 'extract-all': {
        if (args.length !== 3) die('usage: cpz5-pack extract-all <file.cpz> <outDir>');
        cmdExtractAll(args[1], args[2]);
        break;
      }
      case 'build-all': {
        if (args.length !== 4) die('usage: cpz5-pack build-all <original.cpz> <inDir> <out.cpz>');
        cmdBuildAll(args[1], args[2], args[3]);
        break;
      }
      case 'help':
      case '--help':
      case '-h':
      case undefined:
        cmdHelp();
        break;
      default:
        console.error(`unknown command: ${cmd}\n`);
        cmdHelp();
        process.exit(1);
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`error: ${msg}`);
    process.exit(1);
  }
}

main(process.argv);
