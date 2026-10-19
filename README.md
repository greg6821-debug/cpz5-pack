<div align="center">

# cpz5-pack

**Упаковщик/распаковщик архивов `.cpz` для игры happymaher (regret end)**

Purple Software · CPZ5/CPZ6 · Windows / Linux / macOS

[![CI](https://github.com/greg6821-debug/cpz5-pack/actions/workflows/ci.yml/badge.svg)](https://github.com/greg6821-debug/cpz5-pack/actions/workflows/ci.yml)
[![Release](https://github.com/greg6821-debug/cpz5-pack/actions/workflows/release.yml/badge.svg)](https://github.com/greg6821-debug/cpz5-pack/actions/workflows/release.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-green)](#запуск)

</div>

---

## О проекте

Инструмент для моддинга игры **happymaher (regret end)** от Purple Software.
Позволяет извлечь файлы (картинки `.pb3`, звуки `.ogg`, скрипты) из
зашифрованного архива `.cpz`, отредактировать картинки и запаковать всё
обратно в архив, который игровой движок примет без ошибок.

### Ключевые возможности

- ✅ **Полная перепаковка**
- ✅ **Автоопределение плагина** — 5v1 / 5v2 / v6 (CPZ5/CPZ6)
- ✅ **Декодер `.pb3`** — все 6 подверсий (v1/v2/v3/v5/v6), включая JBP1
  (собственный JPEG с DCT, Хаффманом, YCbCr→RGB)
- ✅ **Конвертация `.pb3` ↔ `.png`**
- ✅ **Универсальные команды** — распаковка/сборка за один вызов
- ✅ **Проверка `roundtrip`** — доказывает корректность для конкретного файла
- ✅ **Без зависимостей** — один `.exe` для Windows (или бинарник для Linux/macOS)

### Как это работает

Декодер получен обратной разработкой [arc_unpacker](https://github.com/vn-tools/arc_unpacker)
(GPL-3.0). Все криптопреобразования CPZ5 (`decrypt_1a/1b/1c/2/3`) **обратимы** —
это позиционно-зависимые XOR/поворот/сложение/вычитание. Поэтому шифратор —
точное математическое обращение декодера.

---

## Быстрый старт

### 1. Скачайте бинарник

Со страницы [Releases](../../releases) скачайте файл для вашей ОС:

| Файл | Платформа |
|------|-----------|
| `cpz5-pack.exe` | Windows x64 |
| `cpz5-pack-linux` | Linux x64 |
| `cpz5-pack-macos` | macOS x64 |

### 2. Распакуйте архив игры

```bash
cpz5-pack.exe roundtrip game.cpz            # проверка (обязательно!)
cpz5-pack.exe extract-all game.cpz out\     # распаковка + .pb3→.png
```

После этого в папке `out\` будут:
- `.png` файлы (картинки, можно редактировать)
- `.ogg` файлы (звуки)
- прочие файлы (скрипты и т. д.)
- `manifest.json` (список содержимого)

### 3. Отредактируйте картинки

Откройте `.png` файлы в любом редакторе (Photoshop, GIMP, Paint.NET, Aseprite).
Сохраните изменения.

### 4. Запакуйте обратно

```bash
cpz5-pack.exe build-all game.cpz out\ game.new.cpz
```

### 5. Замените файл в игре

Скопируйте `game.new.cpz` в папку игры вместо оригинального `game.cpz`.
Запустите игру. 

---

## Команды

### Основные

| Команда | Описание |
|---------|----------|
| `roundtrip <файл.cpz>` | Самотест: распаковать → запаковать → сравнить байт-в-байт |
| `list <файл.cpz>` | Показать содержимое архива (версия, плагин, дерево файлов) |
| `unpack <файл.cpz> <папка>` | Распаковать все файлы в папку |
| `repack <оригинал.cpz> <папка> <результат.cpz>` | Запаковать папку в `.cpz` |

### Конвертация изображений

| Команда | Описание |
|---------|----------|
| `pb3topng <папка>` | Все `.pb3` → `.png` (рекурсивно) |
| `pngtopb3 <папка>` | Все `.png` → `.pb3` (движок принимает PNG в слотах `.pb3`) |
| `pb3info <файл.pb3>` | Информация о `.pb3` (тип, размеры, глубина) |

### Универсальные (комбо)

| Команда | Описание |
|---------|----------|
| `extract-all <файл.cpz> <папка>` | `unpack` + `pb3topng` + удаление декодированных `.pb3` |
| `build-all <оригинал.cpz> <папка> <результат.cpz>` | `pngtopb3` + удаление `.png` + `repack` |

### Примеры

```bash
# Быстрый цикл (2 команды):
cpz5-pack.exe extract-all game.cpz out\
# ... редактируем out\image.png ...
cpz5-pack.exe build-all game.cpz out\ game.new.cpz

# По шагам (4 команды, больше контроля):
cpz5-pack.exe unpack game.cpz out\
cpz5-pack.exe pb3topng out\
# ... редактируем ...
cpz5-pack.exe pngtopb3 out\
cpz5-pack.exe repack game.cpz out\ game.new.cpz

# Только данные (без конвертации картинок):
cpz5-pack.exe unpack game.cpz out\
cpz5-pack.exe repack game.cpz out\ game.new.cpz
```

---

## Про формат `.pb3`

`.pb3` — собственный формат картинок Purple Software (magic `PB3B`).
Поддерживаемые подверсии:

| Версия | Описание |
|--------|----------|
| **v1** | LZSS-блоки 16×16, по-канальное кодирование (BGR) |
| **v2** | JBP1 (custom JPEG) + RLE-маска альфа-канала |
| **v3** | JBP1 только (без маски) |
| **v5** | LZSS + дельта-кодирование по каналам |
| **v6** | Overlay поверх базового изображения (с загрузкой по имени) |

JBP1 — это собственная реализация JPEG: DCT, дерево Хаффмана,
YCbCr→RGB с фиксированной запятой. Декодер портирован из `jbp1.cc`
(arc_unpacker).

### Почему `pngtopb3` просто копирует файл?

Движок happymaher имеет **двойной загрузчик** для `.pb3`-слотов: он пробует
и `Pb3ImageDecoder`, и `PngImageDecoder`. 
Поэтому можно положить сырой PNG-файл с расширением `.pb3` —
движок его прочитает. Это значительно проще, чем пере-кодировать PNG
в собственный формат pb3.

---

## Сборка из исходников

### Требования

- [Bun](https://bun.sh) 1.1+

### Сборка

```bash
git clone https://github.com/greg6821-debug/cpz5-pack.git
cd cpz5-pack
bun install

# Запуск через bun:
bun run src/cli.ts help

# Сборка бинарника для текущей ОС:
bun build --compile src/cli.ts --outfile cpz5-pack

# Кросс-компиляция:
bun build --compile --target=bun-windows-x64 src/cli.ts --outfile cpz5-pack.exe
bun build --compile --target=bun-linux-x64   src/cli.ts --outfile cpz5-pack-linux
bun build --compile --target=bun-darwin-x64  src/cli.ts --outfile cpz5-pack-macos
```

### Тестирование

```bash
bun run src/selftest.ts
```

Тест проверяет:
- MD5 с кастомным IV против `node:crypto`
- Круговую совместимость (encoder ↔ decoder) для всех криптофункций
- Roundtrip синтетического архива (байт-в-байт)
- Перепаковку с изменением размера файла

---

## Структура проекта

```
cpz5-pack/
├── src/
│   ├── cli.ts          # CLI: разбор аргументов, команды
│   ├── cpz5.ts         # Ядро: MD5-custom-IV, plugins, encrypt/decrypt, unpack/repack
│   ├── pb3.ts          # Декодер PB3 (v1-v6) + JBP1 (DCT/Huffman/YCbCr)
│   ├── pngenc.ts       # Минимальный PNG-энкодер (zlib + CRC32)
│   └── selftest.ts     # Автотесты (25 проверок)
├── ref/
│   └── refdec.cpp      # C++ эталонный декодер (для верификации)
├── .github/workflows/
│   ├── ci.yml          # CI: тест на каждый push/PR
│   └── release.yml     # Release: сборка бинарников по тегу v*
├── package.json
├── LICENSE             # GPL-3.0
└── README.md
```

---

## Ограничения

- Тестировалось на **happymaher (regret end)**. Должно работать и с другими
  играми Purple Software на движке CPZ5/CPZ6, но не проверялось.
- Менять **имена/количество файлов** нельзя — `repack` сохраняет структуру
  оригинального архива. Можно только заменять содержимое (размер может меняться —
  смещения пересчитываются автоматически).
- Пути в архиве — **Shift-JIS**; инструмент декодирует их в UTF-8 для имён
  файлов (NTFS поддерживает Unicode, обратная упаковка совпадает).
- `.pb3` **v6 (overlay)** при декодировании пытается загрузить базовое
  изображение из той же папки (по имени файла). Если базовый файл не найден —
  overlay накладывается на прозрачный фон.
- Сначала **`roundtrip`**, потом `repack`/`build-all`. Если `roundtrip` падает —
  не перепаковывайте, [сообщите](issues) diff (смещение первого отличия).

---



## Благодарности

- [arc_unpacker](https://github.com/vn-tools/arc_unpacker) (GPL-3.0) —
  исходный декодер, на котором основан этот проект
- [CMVS-Engine](https://github.com/xmoezzz/CMVS-Engine) —
  референсная реализация CPZ6 unpacker

---

## Лицензия

**GPL-3.0** — в силу производности от arc_unpacker. См. [LICENSE](LICENSE).
