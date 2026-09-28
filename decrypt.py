#!/usr/bin/env python3
"""Zone Nova master data decryptor.

Decrypts the AES-256-CBC encrypted master data blob of Zone Nova
(com.yro.novazone.erolab). Works for the live server-downloaded blob
(hash-named .ab, magic b5 61 2a 39 2a 41 b8 09), the APK built-in copy,
and the avg-master-data TextAsset.

Usage:
    python decrypt.py <input> [-o output.bin]
"""
import argparse
import hashlib
import sys
from pathlib import Path

# --- verified constants -----------------------------------------------------
# Cipher: AES-256-CBC + PKCS7.
# KDF: .NET PasswordDeriveBytes (PBKDF1 extension, SHA-1, 100 iterations).
# The game calls GetBytes(32) then GetBytes(16) on one instance.
PASSWORD = b"zVGyaQ6h9tLzqiD5HJQF"
SALT = bytes([0x93, 0x83, 0x33, 0x72])
MAGIC = bytes.fromhex("b5612a392a41b809")

KEY = bytes.fromhex("2c3a1bd0629a269cf539b35d01af6317d5b6302576331a1ad6e7af6414bfc719")
IV = bytes.fromhex("f539b35d01af6317c19d9f69c7f4d1fc")


def pdb_blocks(password: bytes, salt: bytes, iterations: int = 100):
    """Yield the 20-byte stream blocks of .NET PasswordDeriveBytes (SHA-1).

    Mirrors the shipped .NET Framework behavior:
      initial = SHA1(password || salt)
      base    = SHA1 applied (iterations - 2) more times to initial
      block0  = SHA1(base)                       # "last iteration" of PBKDF1
      blockN  = SHA1(ascii_decimal(N) || base)   # N >= 1, base is NOT updated
    """
    base = hashlib.sha1(password + salt).digest()
    for _ in range(iterations - 2):
        base = hashlib.sha1(base).digest()
    counter = 0
    while True:
        if counter == 0:
            yield hashlib.sha1(base).digest()
        else:
            yield hashlib.sha1(str(counter).encode("ascii") + base).digest()
        counter += 1


def game_key_iv():
    """Reproduce the game's GetBytes(32) + GetBytes(16) sequence.

    The IV is shaped by a .NET Framework leftover-buffer bug in
    PasswordDeriveBytes.GetBytes: when the second call does not fit in the
    leftover bytes, it copies from the leftover buffer at index
    (bytes_available) instead of (bytes_already_consumed), resurfacing
    block0[8:16], then continues with the next fresh block.
    """
    blocks = pdb_blocks(PASSWORD, SALT)
    b0 = next(blocks)
    b1 = next(blocks)
    b2 = next(blocks)
    key = b0 + b1[:12]          # GetBytes(32)
    iv = b0[8:16] + b2[:8]      # GetBytes(16) after it (the quirk)
    return key, iv


def strip_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("ciphertext length is not a multiple of the AES block size")
    pad = data[-1]
    if not (1 <= pad <= 16) or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS7 padding (wrong key or not this format)")
    return data[:-pad]


def decrypt(data: bytes, key: bytes = KEY, iv: bytes = IV) -> bytes:
    from Crypto.Cipher import AES

    return strip_pkcs7(AES.new(key, AES.MODE_CBC, iv).decrypt(data))


def main() -> int:
    ap = argparse.ArgumentParser(description="Zone Nova master data decryptor")
    ap.add_argument("input", help="encrypted master data file (magic b5 61 2a 39 ...)")
    ap.add_argument("-o", "--output", help="output file (default: <input>.dec.bin)")
    args = ap.parse_args()

    # Self-check the derivation port against the verified constants.
    dk, div = game_key_iv()
    if (dk, div) != (KEY, IV):
        print("ERROR: derivation self-check failed", file=sys.stderr)
        return 2

    src = Path(args.input)
    data = src.read_bytes()
    if not data.startswith(MAGIC):
        print(f"warning: {src.name} does not start with the expected magic "
              f"{MAGIC.hex()}; trying anyway", file=sys.stderr)

    plain = decrypt(data)
    out = Path(args.output) if args.output else src.with_suffix(src.suffix + ".dec.bin")
    out.write_bytes(plain)
    print(f"decrypted {len(data)} -> {len(plain)} bytes: {out}")
    print("next: python dump_tables.py <output> <outdir>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
