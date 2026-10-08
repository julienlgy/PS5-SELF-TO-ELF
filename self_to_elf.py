#!/usr/bin/env python3
"""Convert raw SELF PRX files in place, preserving originals as .prx.bak."""

import argparse
import os
from pathlib import Path
import struct
import sys
import tempfile


SELF_MAGIC = bytes.fromhex("4f153d1d")
SELF_MAGICS = (SELF_MAGIC, bytes.fromhex("5414f5ee"))
ELF_MAGIC = b"\x7fELF"
DEFAULT_MAX_SIZE = 512 * 1024 * 1024


def describe_format(header):
    magic = header[:4]
    if magic in SELF_MAGICS:
        return f"SELF container ({magic.hex(' ').upper()})"
    if magic in (ELF_MAGIC, b"PELF"):
        label = "PSP PELF" if magic == b"PELF" else "ELF"
        if len(header) >= 20 and header[5] in (1, 2):
            bits = {1: "32", 2: "64"}.get(header[4], "unknown")
            machine, = struct.unpack_from("<H" if header[5] == 1 else ">H", header, 18)
            architecture = {3: "x86", 8: "MIPS", 62: "x86-64", 183: "AArch64"}.get(
                machine, f"machine {machine}")
            label += f" {bits}-bit {architecture}"
        return label + ("; not a SELF container" if magic == b"PELF" else "; already ELF")
    if magic == b"~PSP":
        return "PSP ~PSP container; unsupported format"
    if header[:2] == b"MZ":
        return "MZ executable (possibly Windows PE); not a SELF container"
    return f"unrecognized format; header: {header[:16].hex(' ') or '(empty file)'}"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fits(offset, size, limit):
    return offset <= limit and size <= limit - offset


def overlaps(first, second):
    offset, size = first
    other, length = second
    return size != 0 and length != 0 and offset < other + length and other < offset + size


def covered(offset, size, copies):
    end = offset + size
    while offset < end:
        next_offset = max(
            (start + length for start, length, _ in copies
             if start <= offset < start + length),
            default=offset,
        )
        if next_offset == offset:
            return False
        offset = next_offset
    return True


def self_to_elf(data, max_size=DEFAULT_MAX_SIZE, notices=None):
    """Reconstruct ELF offsets; do not decrypt or decompress SELF payloads."""
    require(data[:4] in SELF_MAGICS, "not a supported SELF file")
    require(max_size > 0, "ELF output size limit must be positive")
    require(len(data) >= 32, "truncated SELF header")
    require(data[4:12] == bytes.fromhex("0001011201010000"),
            "unsupported SELF version/encoding")
    header_size, metadata_size, self_size = struct.unpack_from("<HHQ", data, 12)
    entry_count, = struct.unpack_from("<H", data, 24)
    elf_offset = 32 + entry_count * 32
    payload_start = header_size + metadata_size
    require(payload_start <= self_size <= len(data), "invalid SELF size/metadata")
    require(entry_count > 0 and fits(32, entry_count * 32, header_size),
            "invalid SELF segment table")
    require(fits(elf_offset, 64, header_size), "truncated embedded ELF header")
    elf = struct.unpack_from("<16sHHIQQQIHHHHHH", data, elf_offset)
    require(elf[0][:7] == ELF_MAGIC + b"\x02\x01\x01"
            and elf[2] == 62 and elf[3] == 1 and elf[8] == 64,
            "expected little-endian ELF64 x86-64")
    ph_offset, ph_size, ph_count = elf[5], elf[9], elf[10]
    require(ph_size == 56 and 0 < ph_count < 0xffff and ph_offset >= 64
            and fits(ph_offset, ph_count * 56, header_size - elf_offset),
            "invalid ELF program-header table")
    elf_header_size = ph_offset + ph_count * 56
    require(elf_header_size <= max_size, "ELF header exceeds output size limit")
    headers = [
        struct.unpack_from("<IIQQQQQQ", data, elf_offset + ph_offset + i * 56)
        for i in range(ph_count)
    ]
    for i, header in enumerate(headers):
        kind, _, offset, address, _, size, memory_size, _ = header
        require(fits(offset, size, (1 << 64) - 1)
                and fits(address, memory_size, (1 << 64) - 1),
                f"program header {i}: range overflow")
        require(kind != 1 or size <= memory_size,
                f"program header {i}: load payload exceeds memory size")

    entries = [
        struct.unpack_from("<QQQQ", data, 32 + i * 32)
        for i in range(entry_count)
    ]
    copies = [(0, elf_header_size, elf_offset)]
    sources = []
    assigned = set()
    for i, (flags, source, stored_size, unpacked_size) in enumerate(entries):
        name = f"segment {i}"
        require(not flags & 2, f"{name}: encrypted; no decryption is performed")
        require(not flags & 8, f"{name}: compressed; provide an uncompressed SELF")
        attributes = flags & 0xfffff
        digest = attributes == 0x10004
        require(flags >> 32 == 0 and (
            digest or attributes == 4 or attributes & ~0xf000 == 0x804),
            f"{name}: unsupported flags {flags:#x}")
        require(source >= payload_start and fits(source, stored_size, self_size),
                f"{name}: payload outside SELF")
        require(stored_size == unpacked_size, f"{name}: inconsistent raw size")
        require(not any(overlaps((source, stored_size), previous) for previous in sources),
                f"{name}: overlapping SELF payload")
        sources.append((source, stored_size))
        index = (flags >> 20) & 0xfff
        if digest:
            require(index < entry_count and not entries[index][0] & 0x10000,
                    f"{name}: invalid digest target")
            continue
        require(index < ph_count and index not in assigned,
                f"{name}: invalid or duplicate ELF mapping")
        assigned.add(index)
        destination, size = headers[index][2], headers[index][5]
        require(size == unpacked_size, f"{name}: size differs from ELF header")
        require(fits(destination, size, max_size), f"{name}: exceeds output size limit")
        require(not any(overlaps((destination, size), (start, length))
                        for start, length, _ in copies),
                f"{name}: overlapping ELF payload")
        copies.append((destination, size, source))

    # Some dumped containers append a complete SCE COMMENT after selfSize.
    tail_size = len(data) - self_size
    if tail_size:
        candidates = [i for i, header in enumerate(headers)
                      if header[0] == 0x6fffff01 and i not in assigned]
        require(len(candidates) == 1,
                "unsupported unsigned SELF trailer")
        comment = headers[candidates[0]]
        destination, declared_size = comment[2], comment[5]
        if tail_size == declared_size:
            require(fits(destination, tail_size, max_size), "trailer exceeds output size limit")
            require(not any(overlaps((destination, tail_size), (start, length))
                            for start, length, _ in copies),
                    "trailer overlaps ELF payload")
            copies.append((destination, tail_size, self_size))
        else:
            require(tail_size < declared_size and comment[1] == 0 and comment[3] == 0,
                    "unsupported unsigned SELF trailer")
            # A truncated, non-loadable comment cannot supply runtime bytes.
            # Strip its header instead of inventing the missing metadata.
            if notices is not None:
                notices.append(f"stripped incomplete SCE COMMENT ({tail_size}/{declared_size} bytes)")

    omitted = []
    for i, header in enumerate(headers):
        kind, flags, offset, address, _, size, memory_size, _ = header
        if kind == 0 or size == 0 or covered(offset, size, copies):
            continue
        optional = flags == 0 and address == 0 and (
            (kind == 4 and memory_size == 0) or kind in (0x6fffff00, 0x6fffff01))
        require(optional and not any(overlaps((offset, size), (start, length))
                                    for start, length, _ in copies),
                f"missing payload for program header {i}")
        omitted.append(i)

    output_size = max(start + size for start, size, _ in copies if size)
    output = bytearray(output_size)
    for destination, size, source in copies:
        output[destination:destination + size] = data[source:source + size]
    # Reconstruct the runtime segments as a stripped ELF: SELF does not
    # guarantee that the original section table or debug payloads survive.
    struct.pack_into("<Q", output, 40, 0)
    struct.pack_into("<HHH", output, 58, 0, 0, 0)
    for i in omitted:
        position = ph_offset + i * 56
        output[position:position + 56] = bytes(56)
    for i, header in enumerate(headers):
        if header[0] == 0:
            position = ph_offset + i * 56
            output[position:position + 56] = bytes(56)
        elif header[5] == 0 and header[2] > output_size:
            # Empty runtime segments have no file payload, but readers still
            # require their file offset to be within the reconstructed ELF.
            struct.pack_into("<Q", output, ph_offset + i * 56 + 8, 0)
    validate_elf(output)
    return output


def validate_elf(data):
    require(len(data) >= 64 and data[:7] == ELF_MAGIC + b"\x02\x01\x01",
            "expected little-endian ELF64")
    elf = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    require(elf[2] == 62 and elf[3] == 1 and elf[8] == 64,
            "expected ELF64 x86-64")
    ph_offset, ph_size, ph_count = elf[5], elf[9], elf[10]
    require(ph_size == 56 and ph_offset >= 64 and 0 < ph_count < 0xffff
            and fits(ph_offset, ph_count * ph_size, len(data)),
            "invalid ELF program-header table")
    loads = []
    for i in range(ph_count):
        kind, flags, offset, address, _, size, memory_size, alignment = struct.unpack_from(
            "<IIQQQQQQ", data, ph_offset + i * ph_size)
        require(fits(offset, size, len(data)), f"ELF program header {i}: payload outside file")
        if kind != 1:
            continue
        require(size <= memory_size and flags & ~7 == 0,
                f"ELF program header {i}: invalid load segment")
        require(fits(address, memory_size, (1 << 64) - 1),
                f"ELF program header {i}: memory range overflow")
        require(alignment <= 1 or (
            alignment & (alignment - 1) == 0 and offset % alignment == address % alignment),
            f"ELF program header {i}: invalid load alignment")
        require(not any(overlaps((address, memory_size), previous) for previous in loads),
                f"ELF program header {i}: overlapping load memory")
        loads.append((address, memory_size))


def repair_empty_null_headers(data):
    """Repair dangling PT_NULL offsets left by earlier versions of this tool."""
    if len(data) < 64 or data[:7] != ELF_MAGIC + b"\x02\x01\x01":
        return None
    ph_offset, = struct.unpack_from("<Q", data, 32)
    ph_size, ph_count = struct.unpack_from("<HH", data, 54)
    require(ph_size == 56 and fits(ph_offset, ph_count * ph_size, len(data)),
            "invalid ELF program-header table")
    output = None
    for i in range(ph_count):
        position = ph_offset + i * ph_size
        kind, flags, offset, address, _, size, memory_size, _ = struct.unpack_from(
            "<IIQQQQQQ", data, position)
        if (kind == 0 and flags == 0 and address == 0 and size == 0
                and memory_size == 0 and offset > len(data)):
            if output is None:
                output = bytearray(data)
            output[position:position + ph_size] = bytes(ph_size)
    if output is not None:
        validate_elf(output)
    return output


def replace_with_backup(path, output, backup):
    require(not os.path.lexists(backup), f"backup already exists: {backup}")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
                dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
        # A hard link preserves the original and atomically refuses an existing backup.
        os.link(path, backup)
        try:
            os.replace(temporary, path)
        except OSError:
            backup.unlink()
            raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def convert_file(path, max_size, dry_run):
    require(not path.is_symlink(), "symbolic links are not supported")
    with path.open("rb") as stream:
        original_stat = os.fstat(stream.fileno())
        header = stream.read(64)
        magic = header[:4]
        if magic != ELF_MAGIC and magic not in SELF_MAGICS:
            return "SKIP", describe_format(header)
        stream.seek(0)
        data = stream.read()
    notices = []
    if magic == ELF_MAGIC:
        output = repair_empty_null_headers(data)
        if output is None:
            return "SKIP", describe_format(header)
        backup = path.with_name(path.name + ".elf.bak")
        action = "REPAIRED"
    else:
        output = self_to_elf(data, max_size, notices)
        backup = path.with_name(path.name + ".bak")
        action = "OK"
    require(not os.path.lexists(backup), f"backup already exists: {backup}")
    details = "; " + "; ".join(notices) if notices else ""
    if dry_run:
        return "READY", f"{action}: ELF {len(output)} bytes; backup: {backup.name}{details}"
    current_stat = path.stat()
    require((original_stat.st_dev, original_stat.st_ino, original_stat.st_size,
             original_stat.st_mtime_ns) ==
            (current_stat.st_dev, current_stat.st_ino, current_stat.st_size,
             current_stat.st_mtime_ns),
            "source changed during conversion; refusing to replace it")
    replace_with_backup(path, output, backup)
    return action, f"ELF {len(output)} bytes; original: {backup.name}{details}"


def main():
    parser = argparse.ArgumentParser(
        description="Recursively convert unencrypted, uncompressed SELF *.prx "
                    "(4F 15 3D 1D or 54 14 F5 EE) to ELF, preserving originals "
                    "as *.prx.bak. No decryption or decompression is performed. Also repair "
                    "dangling empty PT_NULL headers in previously converted ELF "
                    "(backup: *.prx.elf.bak).")
    parser.add_argument("path", type=Path, help="directory to scan, or a single .prx file")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate conversions without modifying files")
    parser.add_argument("--max-output-mib", type=int, default=512,
                        help="maximum reconstructed size per ELF (default: 512 MiB)")
    args = parser.parse_args()
    if args.max_output_mib <= 0:
        parser.error("--max-output-mib must be positive")
    root = args.path.resolve()
    if root.is_dir():
        paths = sorted(path for path in root.rglob("*")
                       if path.suffix.lower() == ".prx" and path.is_file())
    elif root.is_file() and root.suffix.lower() == ".prx":
        paths = [root]
    else:
        parser.error("path must be an existing directory or .prx file")
    totals = {"OK": 0, "REPAIRED": 0, "READY": 0, "SKIP": 0, "FAIL": 0}
    for path in paths:
        try:
            status, message = convert_file(path, args.max_output_mib * 1024 * 1024, args.dry_run)
        except (OSError, ValueError) as error:
            status, message = "FAIL", str(error)
        totals[status] += 1
        print(f"{status}: {path}: {message}", file=sys.stderr if status == "FAIL" else sys.stdout)
    print(f"Converted={totals['OK']}; repaired={totals['REPAIRED']}; ready={totals['READY']}; "
          f"skipped={totals['SKIP']}; failed={totals['FAIL']}")
    return 1 if totals["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
