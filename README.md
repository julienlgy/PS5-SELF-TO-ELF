# PS5 SELF to ELF Converter

A Python tool to convert **unencrypted, uncompressed** PS5 SELF (Signed Executable and Linkable Format) `.prx` files to standard ELF executables, preserving the originals as backups.

## Overview

The PlayStation 5 uses SELF containers to package executables. This tool reconstructs the original ELF binary from a SELF container by:

- Parsing the SELF header and segment table
- Mapping SELF payload segments to ELF program headers
- Reconstructing a valid ELF64 x86-64 executable
- Preserving the original file as a `.prxbak` backup

**Important:** This tool does **not** decrypt encrypted SELF files or decompress compressed payloads. It only works on unencrypted, uncompressed SELF containers.

## Features

- ✅ Converts SELF `.prx` files (magic `4F 15 3D 1D` or `54 14 F5 EE`) to ELF
- ✅ Recursively processes directories
- ✅ Preserves originals as `.prxbak` backups
- ✅ Repairs dangling `PT_NULL` headers in previously converted ELF files (backup: `.prx.elf.bak`)
- ✅ Validates output ELF structure
- ✅ Dry-run mode for safe testing
- ✅ Configurable output size limit (default: 512 MiB)

## Requirements

- Python 3.8+

## Installation

```bash
git clone https://github.com/julienlgy/PS5-SELF-TO-ELF.git
cd PS5-SELF-TO-ELF
```

No additional dependencies required — uses only Python standard library.

## Usage

```bash
# Convert all .prx files in a directory (recursive)
python self_to_elf.py /path/to/ps5/game/directory

# Convert a single .prx file
python self_to_elf.py /path/to/file.prx

# Dry run (validate without modifying files)
python self_to_elf.py /path/to/directory --dry-run

# Custom output size limit (in MiB)
python self_to_elf.py /path/to/directory --max-output-mib 1024
```

### Example

```bash
$ python self_to_elf.py ./app0/
OK: ./app0/eboot.prx: ELF 2457600 bytes; original: eboot.prxbak
OK: ./app0/libSceSysmodule.prx: ELF 102400 bytes; original: libSceSysmodule.prxbak
SKIP: ./app0/data.bin: unrecognized format; header: 00 00 00 00 ...
Converted=2; repaired=0; ready=0; skipped=1; failed=0
```

## Output Status Codes

| Status | Meaning |
|--------|---------|
| `OK` | Successfully converted SELF to ELF |
| `REPAIRED` | Fixed dangling PT_NULL headers in existing ELF |
| `READY` | Dry-run: conversion would succeed |
| `SKIP` | Not a SELF file or already valid ELF |
| `FAIL` | Conversion error (encrypted, compressed, corrupt, etc.) |

## Limitations

- ❌ **No decryption** — Encrypted SELF files (flag `0x2`) are rejected
- ❌ **No decompression** — Compressed payloads (flag `0x8`) are rejected
- ❌ **PSP `~PSP` containers** — Not supported
- ❌ **Windows PE / MZ executables** — Not supported

## How It Works

1. **Detection** — Identifies SELF files by magic bytes (`4F 15 3D 1D` or `54 14 F5 EE`)
2. **Validation** — Verifies SELF header, version, and segment table integrity
3. **Mapping** — Matches SELF segment entries to ELF program headers
4. **Reconstruction** — Copies payload data to correct ELF offsets
5. **Cleanup** — Strips section headers and zeroes omitted program headers
6. **Validation** — Verifies output is a valid ELF64 x86-64 executable
7. **Backup** — Creates hard-link backup before atomic replacement

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Pull requests welcome! Please ensure:
- Code passes existing validation logic
- New features include appropriate tests
- Documentation is updated for user-facing changes