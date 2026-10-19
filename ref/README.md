# Reference decoder (refdec.cpp)

`refdec.cpp` — C++ эталонный декодер CPZ5, переписанный напрямую из исходников
[arc_unpacker](https://github.com/vn-tools/arc_unpacker)
(`purple_software/cpz5/crypt.cc` + `plugin.cc` + `algo/crypt/md5.cc`),
использующий OpenSSL MD5.

## Назначение

Используется для **верификации** TypeScript-декодера (`src/cpz5.ts`):
если C++-декодер и TS-декодер дают одинаковый результат на одном файле —
TS-порт корректен.

## Сборка

```bash
g++ -O2 -o refdec refdec.cpp -lcrypto
```

Требуется `libssl-dev` (OpenSSL).

## Использование

```bash
./refdec <файл.cpz5> [5v1|5v2|both]
```

Выводит: заголовок, хэш, декодированную таблицу директорий, список файлов
и первые байты распакованных данных.
