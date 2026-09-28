# Zone Nova Extractor

Master data extractor for **Zone Nova** (`com.yro.novazone.erolab`, Erolabs build; Unity 2022.3.62f2 IL2CPP).

This repo covers the part people usually get stuck on: locating the encrypted master data blob, the AES key, and dumping the plaintext tables (including all text/localization tables) to JSON.

## TL;DR (the key)

| Item | Value |
|------|-------|
| Cipher | AES-256-CBC, PKCS7 padding |
| KDF | .NET `PasswordDeriveBytes` (PBKDF1 extension, SHA-1, 100 iterations) |
| Password | `zVGyaQ6h9tLzqiD5HJQF` (UTF-8) |
| Salt | raw 4 bytes `93 83 33 72` |
| KEY | `2c3a1bd0629a269cf539b35d01af6317d5b6302576331a1ad6e7af6414bfc719` |
| IV | `f539b35d01af6317c19d9f69c7f4d1fc` |
| Encrypted file magic | `b5 61 2a 39 2a 41 b8 09` (first 8 bytes) |

The game calls `GetBytes(32)` then `GetBytes(16)` on a single `PasswordDeriveBytes` instance to get KEY and IV. Both values are constant, so the hex above is all you need. `decrypt.py` contains a pure-Python port of the derivation (including a .NET quirk, see below) if you want to re-derive or port it.

## Where the data lives

Two encrypted blobs use the same key:

1. **Live master data** (server-updated, what you want): a hash-named raw `.ab` file inside the game's bundle directory on the device:
   ```
   /sdcard/Android/data/com.yro.novazone.erolab/files/AssetBundles/Source/Android/<SHA1-HASH>.ab
   ```
   It is NOT a Unity bundle (UnityPy silently skips it). Find it by the magic bytes `b5 61 2a 39 2a 41 b8 09`, not by name or mtime. Contains 85 tables including all character/skill/gacha/equipment data and the translation tables.

2. **APK built-in copy** (stale fallback, ships in the base APK): `assets/bin/Data/5efa97d58a629458995b1388bd7d1c94`.

3. **avg-master-data.bytes** (story/AVG system, 2 tables: `avg_translation_ds` ~14.5k rows + `avg_view_info`): a TextAsset inside the UtS-wrapped bundle `14CA4D7A...` in the same directory. Zone Nova bundles are wrapped in a custom `UtS` container (prefix magic `UtS\0` + version string, UnityFS payload embedded at a variable offset): scan for the `UnityFS` magic and feed the tail to UnityPy to get the TextAsset, then decrypt it like the others.

## Quick start

```bash
pip install -r requirements.txt

# 1. Pull the live files from the device/emulator
adb pull /sdcard/Android/data/com.yro.novazone.erolab/files/AssetBundles/Source/Android/ ./pulled/

# 2. Locate the encrypted blob (scans files and zip/apk entries by magic)
python find_masterdata.py ./pulled

# 3. Decrypt
python decrypt.py ./pulled/DE8EE416....ab -o master-data.bin

# 4. Dump all tables to JSON
python dump_tables.py master-data.bin ./tables
```

Windows PowerShell alternative (uses .NET's `PasswordDeriveBytes` natively, no Python needed):

```powershell
powershell -File decrypt.ps1 -In .\pulled\DE8EE416....ab -Out .\master-data.bin
```

### The text files

Localization lives in these dumped tables (one JSON per table):

- `translation_ds.json`, `translation_ui.json`, `translation_uilabel.json`: rows like `["CHARACTER_NAME_3001", "莎椰", "Saya", "サヤ", "莎椰"]` (key, zh-CN, EN, JA, zh-TW)
- `avg_translation_ds.json`: story/AVG dialogue strings
- Everything else (skill descriptions, item names, gacha text, ...) resolves through the same translation tables by key.

## Decryption details

The derivation, exactly as the game does it (SHA-1, 100 iterations, PBKDF1 + the .NET extension):

1. `initial = SHA1(password || salt)`
2. `base = SHA1^98(initial)` (so `base = SHA1^99(password || salt)`)
3. Stream blocks of 20 bytes:
   - block 0 = `SHA1(base)` (the "last iteration" of PBKDF1)
   - block n (n >= 1) = `SHA1(ascii_decimal(n) || base)`, e.g. block 1 = `SHA1("1" || base)`
4. Game pattern `GetBytes(32)` then `GetBytes(16)` on one instance:
   - `KEY = block0 || block1[0:12]`
   - `IV = block0[8:16] || block2[0:8]`

Step 4's IV looks wrong and it is: .NET Framework's `PasswordDeriveBytes.GetBytes` has a leftover-buffer bug (`Buffer.InternalBlockCopy(_extra, ib, ...)` uses the byte-count `ib` where it should use the offset `_extraCount`, kept for V1.x compat). When the second `GetBytes` call needs more bytes than the leftover can supply, it copies from the wrong offset, which resurfaces bytes 8..16 of block 0 and then continues with a fresh block. The constants above already bake this in; `decrypt.py` reproduces it and self-checks against the known KEY/IV.

## How the key was found

Static il2cpp analysis (Frida does not work on the target BlueStacks instance):

- Decrypt routine: obfuscated class `FEAPPKCFGPC.KEGLKNGBKDC` at RVA `0x37DAA18` in `libil2cpp.so`; calls into `AesManaged` with a `PasswordDeriveBytes`.
- Password: comes from a metadata string slot. Resolve the `adrp+ldr` slot through the `.rela.dyn` R_AARCH64_RELATIVE addend, look the address up in Il2CppDumper's `script.json` `ScriptString` table, read the literal.
- Salt: a `<PrivateImplementationDetails>` field default (4 bytes). Field default data is reachable via the metadata fields table -> fieldDefaultValues -> fieldAndParameterDefaultValueData. The Roslyn compiler names such fields after the SHA-256 of their data, which lets you verify candidates.

## Plaintext format (MasterMemory container)

Decrypted output is a [MasterMemory](https://github.com/Cysharp/MasterMemory) / MessagePack-CSharp stream:

- Header: msgpack map `{tableName(str): [offset(i32), length(i32)]}`, offsets relative to the END of the header object.
- Each table region: either a raw msgpack array of rows, or an LZ4 block wrapped as msgpack extension type 99: `[d2 rawSize][lz4 data]`.
- Rows are POSITIONAL arrays; column meanings come from the game's row classes (visible in an Il2CppDumper `dump.cs`, e.g. the builder class named `KMCOLPAJAMN`). Example translation row: `["KEY", "zh-CN", "EN", "JA", "zh-TW"]`.

Notable tables: `character_data_info`, `character_skill_data_info`, `character_talent_info`, `character_awaken_info`, `remembrance_info` (memory cards), `gacha_info`, `equipment_info`, `passive_data_info`, `buff_data_info`, `rift_info`, `tower_info`, `quest_info`, `mission_info`, `stack_item_info`, `enemy_spawn_detail_info`, `translation_ds/ui/uilabel`, ...

## Files

| File | Purpose |
|------|---------|
| `find_masterdata.py` | Scan a directory (or zip/apk) for files starting with the AES magic |
| `decrypt.py` | Pure-Python decryptor with verified constants + derivation port |
| `decrypt.ps1` | PowerShell decryptor using .NET `PasswordDeriveBytes` directly |
| `dump_tables.py` | MasterMemory container -> one JSON per table + `_index.json` |

## Notes

- Erolabs R18 game; the same key works for the live blob, the APK builtin copy, and the avg master data.
- The game updates every ~14 days and ships new tables into the live blob; the APK copy goes stale on first update.
- Re-pull with adb after letting the game download updates in-game.
