#!/usr/bin/env python3
"""Dump Zone Nova's decrypted master data (MasterMemory container) to JSON.

Container format (MasterMemory, MessagePack-CSharp):
  header = msgpack map {tableName(str): [offset(int32), length(int32)]}
  each table region = either a raw msgpack array of rows, or an LZ4Block:
  msgpack extension type 99 = [int32 rawSize][lz4 block stream]

Usage:
    python dump_tables.py <decrypted.bin> [outdir]
"""
import json
import struct
import sys
from pathlib import Path

import lz4.block
import msgpack

SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("master-data.bin")
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("tables")
OUT.mkdir(parents=True, exist_ok=True)

data = SRC.read_bytes()
unpacker = msgpack.Unpacker(raw=False, strict_map_key=False)
unpacker.feed(data)
header = next(unpacker)  # first object only; tables follow in the same stream
base = unpacker.tell()   # table offsets are relative to the end of the header
print(f"header: {len(header)} tables, data base offset {base}")

index = {}
for name, (off, length) in sorted(header.items(), key=lambda kv: kv[1][0]):
    region = data[base + off:base + off + length]
    first = region[0]
    if first in (0xC7, 0xC8, 0xC9):  # ext8/ext16/ext32
        if first == 0xC7:
            elen, etype, pstart = region[1], region[2], 3
        elif first == 0xC8:
            elen, etype, pstart = struct.unpack_from(">H", region, 1)[0], region[3], 4
        else:
            elen, etype, pstart = struct.unpack_from(">I", region, 1)[0], region[5], 6
        payload = region[pstart:pstart + elen]
        if etype == 99:
            if payload[0] == 0xD2:  # msgpack int32 (marker + 4 value bytes)
                raw_size = struct.unpack_from(">i", payload, 1)[0]
                lz4_data = payload[5:]
            else:                   # raw LE int32
                raw_size = struct.unpack_from("<i", payload, 0)[0]
                lz4_data = payload[4:]
            rows = msgpack.unpackb(
                lz4.block.decompress(lz4_data, uncompressed_size=raw_size),
                raw=False, strict_map_key=False)
        else:
            rows = msgpack.unpackb(region, raw=False, strict_map_key=False)
    else:
        u = msgpack.Unpacker(raw=False, strict_map_key=False)
        u.feed(region)
        rows = next(u)
    nrows = len(rows) if isinstance(rows, (list, dict)) else 1
    index[name] = {"rows": nrows, "bytes": length, "compressed": first in (0xC7, 0xC8, 0xC9)}
    (OUT / f"{name}.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print(f"  {name:40} rows={nrows:6}  bytes={length:9}  first=0x{first:02x}")

(OUT / "_index.json").write_text(json.dumps(index, indent=2))
print(f"\n{len(index)} tables dumped to {OUT}")
