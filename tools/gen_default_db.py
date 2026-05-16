#!/usr/bin/env python3
"""Generate default (empty) AV database files for shipping with the installer."""
import struct
import hashlib
import os
import sys

MANIFEST_MAGIC = b"MF-Mareychenko"
DATA_MAGIC     = b"DB-Mareychenko"
MAGIC_LEN      = 14
FORMAT_VERSION = 1

def write_u8(f, v):
    f.write(struct.pack(">B", v))

def write_u16be(f, v):
    f.write(struct.pack(">H", v))

def write_u32be(f, v):
    f.write(struct.pack(">I", v))

def write_i64be(f, v):
    f.write(struct.pack(">q", v))

def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."

    # data.bin: header only, 0 records
    import io
    data_buf = io.BytesIO()
    data_buf.write(DATA_MAGIC.ljust(MAGIC_LEN, b'\0'))
    write_u16be(data_buf, FORMAT_VERSION)
    write_u32be(data_buf, 0)  # 0 records
    data_bytes = data_buf.getvalue()

    data_sha256 = hashlib.sha256(data_bytes).digest()

    # manifest.bin: header only, 0 entries, no signature
    import time
    mf_buf = io.BytesIO()
    mf_buf.write(MANIFEST_MAGIC.ljust(MAGIC_LEN, b'\0'))
    write_u16be(mf_buf, FORMAT_VERSION)
    write_u8(mf_buf, 0)  # EXPORT_FULL
    write_i64be(mf_buf, int(time.time() * 1000))  # generatedAt
    write_i64be(mf_buf, -1)  # since (N/A)
    write_u32be(mf_buf, 0)   # record count
    mf_buf.write(data_sha256)
    # no entries
    # signature length = 0 (no key available for signing)
    write_u32be(mf_buf, 0)
    mf_bytes = mf_buf.getvalue()

    data_path = os.path.join(outdir, "default_data.bin")
    mf_path   = os.path.join(outdir, "default_manifest.bin")

    with open(data_path, "wb") as f:
        f.write(data_bytes)
    with open(mf_path, "wb") as f:
        f.write(mf_bytes)

    print(f"Generated {mf_path} ({len(mf_bytes)} bytes)")
    print(f"Generated {data_path} ({len(data_bytes)} bytes)")

if __name__ == "__main__":
    main()
