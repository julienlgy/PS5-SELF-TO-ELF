#!/usr/bin/env python3
"""Convert raw SELF PRX files in place, preserving originals as .prxbak."""

import argparse
from dataclasses import dataclass, field
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import time


SELF_MAGIC = bytes.fromhex("4f153d1d")
SELF_MAGICS = (SELF_MAGIC, bytes.fromhex("5414f5ee"))
ELF_MAGIC = b"\x7fELF"
DEFAULT_MAX_SIZE = 512 * 1024 * 1024

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
STYLES = {
    "OK": ("\033[92m", "✔"),
    "REPAIRED": ("\033[96m", "♻"),
    "READY": ("\033[94m", "➜"),
    "SKIP": ("\033[93m", "•"),
    "FAIL": ("\033[91m", "✘"),
}
CYAN = "\033[96m"
SELF_ART = [
    "███████╗███████╗██╗     ███████╗",
    "██╔════╝██╔════╝██║     ██╔════╝",
    "███████╗█████╗  ██║     █████╗  ",
    "╚════██║██╔══╝  ██║     ██╔══╝  ",
    "███████║███████╗███████╗███████╗",
    "╚══════╝╚══════╝╚══════╝╚══════╝",
]
ELF_ART = [
    "███████╗██╗     ███████╗",
    "██╔════╝██║     ██╔════╝",
    "█████╗  ██║     █████╗  ",
    "██╔══╝  ██║     ██╔══╝  ",
    "███████╗███████╗███████╗",
    "╚══════╝╚══════╝╚══════╝",
]


@dataclass
class Result:
    path: Path
    status: str
    size: int = 0
    note: str = ""
    notices: list = field(default_factory=list)


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
    missing_padding = self_size - len(data)
    require(payload_start <= min(self_size, len(data)) and (
        missing_padding <= 0 or
        (missing_padding < 16 and self_size % 16 == 0)),
        "invalid SELF size/metadata")
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
        require(source >= payload_start
                and fits(source, stored_size, min(self_size, len(data))),
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

    if missing_padding > 0 and notices is not None:
        notices.append(f"accepted missing final SELF alignment padding ({missing_padding} bytes)")

    # Some dumped containers append a complete SCE COMMENT after selfSize.
    tail_size = len(data) - self_size
    if tail_size > 0:
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
        optional = is_optional_metadata_segment(kind, flags, address, memory_size)
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


def is_optional_metadata_segment(kind, flags, address, memory_size):
    return flags == 0 and address == 0 and (
        (kind == 4 and memory_size == 0) or kind in (0x6fffff00, 0x6fffff01))


def section_table_error(data, ph_offset=64, ph_count=0):
    """Check section-table metadata and entries, including extended numbering."""
    offset, = struct.unpack_from("<Q", data, 40)
    entry_size, count, names = struct.unpack_from("<HHH", data, 58)
    if offset == 0:
        return "section counts without a section table" if count or names else None
    if entry_size != 64:
        return "invalid ELF section-header entry size"
    if offset < 64 or not fits(offset, entry_size, len(data)):
        return f"section header table at {offset:#x} is truncated"
    if count == 0:
        count, = struct.unpack_from("<Q", data, offset + 32)
        if count == 0 or count >= (1 << 32):
            return "invalid extended ELF section count"
    table_size = count * entry_size
    if not fits(offset, table_size, len(data)):
        return f"section header table at {offset:#x} is truncated"
    if overlaps((offset, table_size), (ph_offset, ph_count * 56)):
        return "ELF section-header table overlaps program-header table"
    if names == 0xffff:
        names, = struct.unpack_from("<I", data, offset + 40)
    if names >= count:
        return "ELF section-name table index outside section table"
    sh0_type, = struct.unpack_from("<I", data, offset + 4)
    if sh0_type != 0:
        return "ELF section 0 is not SHT_NULL"
    strtab_offset = strtab_size = 0
    if names != 0:
        _, sh_type, _, _, strtab_offset, strtab_size = struct.unpack_from(
            "<IIQQQQ", data, offset + names * entry_size)
        if (sh_type != 3 or strtab_size == 0
                or not fits(strtab_offset, strtab_size, len(data))
                or data[strtab_offset + strtab_size - 1] != 0):
            return "ELF section-name string table is invalid or truncated"
    for i in range(1, count):
        sh_name, sh_type, _, _, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, offset + i * entry_size)
        if names != 0 and sh_name >= strtab_size:
            return f"ELF section {i}: name offset outside string table"
        if sh_type not in (0, 8) and not fits(sh_offset, sh_size, len(data)):
            return f"ELF section {i} at {sh_offset:#x} is truncated"
    return None


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
        position = ph_offset + i * ph_size
        raw = data[position:position + ph_size]
        kind, flags, offset, address, _, size, memory_size, alignment = struct.unpack_from(
            "<IIQQQQQQ", raw)
        if kind == 0:
            require(raw == bytes(ph_size), f"ELF program header {i}: non-zero PT_NULL entry")
            continue
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
    error = section_table_error(data, ph_offset, ph_count)
    require(error is None, error)


def repair_elf_headers(data, notices=None):
    """Repair invalid section tables, truncated optional metadata, and dangling program headers."""
    if len(data) < 64 or data[:7] != ELF_MAGIC + b"\x02\x01\x01":
        return None
    elf = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    require(elf[2] == 62 and elf[3] == 1 and elf[8] == 64,
            "expected ELF64 x86-64")
    ph_offset, ph_size, ph_count = elf[5], elf[9], elf[10]
    require(ph_size == 56 and ph_offset >= 64 and 0 < ph_count < 0xffff
            and fits(ph_offset, ph_count * ph_size, len(data)),
            "invalid ELF program-header table")
    output = None
    for i in range(ph_count):
        position = ph_offset + i * ph_size
        raw = data[position:position + ph_size]
        kind, flags, offset, address, _, size, memory_size, _ = struct.unpack_from(
            "<IIQQQQQQ", raw)
        if kind == 0:
            if raw != bytes(ph_size):
                if output is None:
                    output = bytearray(data)
                output[position:position + ph_size] = bytes(ph_size)
                if notices is not None:
                    notices.append(f"cleared non-zero PT_NULL program header {i}")
        elif size == 0 and offset > len(data):
            if output is None:
                output = bytearray(data)
            struct.pack_into("<Q", output, position + 8, 0)
            if notices is not None:
                notices.append(
                    f"reset out-of-range offset {offset:#x} on empty program header {i}")
        elif not fits(offset, size, len(data)) and is_optional_metadata_segment(
                kind, flags, address, memory_size):
            if output is None:
                output = bytearray(data)
            output[position:position + ph_size] = bytes(ph_size)
            if notices is not None:
                notices.append(
                    f"stripped truncated optional program header {i} ({kind:#x} at {offset:#x})")
    error = section_table_error(data, ph_offset, ph_count)
    if error is not None:
        if output is None:
            output = bytearray(data)
        struct.pack_into("<Q", output, 40, 0)
        struct.pack_into("<HHH", output, 58, 0, 0, 0)
        if notices is not None:
            notices.append(f"stripped invalid section-table metadata: {error}")
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
            return Result(path, "SKIP", note=describe_format(header))
        stream.seek(0)
        data = stream.read()
    notices = []
    if magic == ELF_MAGIC:
        output = repair_elf_headers(data, notices)
        if output is None:
            validate_elf(data)
            return Result(path, "SKIP", note=describe_format(header))
        backup = path.with_name(path.name + ".elf.bak")
        status = "REPAIRED"
    else:
        output = self_to_elf(data, max_size, notices)
        backup = path.with_name(path.name + "bak")
        status = "OK"
    require(not os.path.lexists(backup), f"backup already exists: {backup}")
    if dry_run:
        return Result(path, "READY", len(output), f"backup: {backup.name}", notices)
    current_stat = path.stat()
    require((original_stat.st_dev, original_stat.st_ino, original_stat.st_size,
             original_stat.st_mtime_ns) ==
            (current_stat.st_dev, current_stat.st_ino, current_stat.st_size,
             current_stat.st_mtime_ns),
            "source changed during conversion; refusing to replace it")
    replace_with_backup(path, output, backup)
    return Result(path, status, len(output), f"backup: {backup.name}", notices)


def human_size(size):
    if not size:
        return "-"
    for unit in ("B", "KiB", "MiB"):
        if size < 1024:
            return f"{size} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"


def clip(text, width):
    return text if len(text) <= width else text[:width - 1] + "…"


def paint(text, code, enabled):
    return f"{code}{text}{RESET}" if enabled else text


def print_banner(color):
    print()
    for i in range(len(SELF_ART)):
        arrow = "   ══▶   " if i == 2 else "         "
        line = SELF_ART[i] + arrow + ELF_ART[i]
        print(paint("  " + line, BOLD + CYAN, color))
    print(paint("  PS5 SELF/PRX → ELF converter", BOLD, color)
          + paint("  ·  no decryption, no decompression", DIM, color))
    print()


def print_progress(done, total, name):
    width = 30
    filled = int(width * done / total)
    columns = shutil.get_terminal_size((100, 20)).columns - 1
    line = f"  {'█' * filled}{'░' * (width - filled)} {done}/{total}  {name}"[:columns]
    sys.stdout.write("\r" + line.ljust(columns))
    sys.stdout.flush()


def clear_progress():
    columns = shutil.get_terminal_size((100, 20)).columns - 1
    sys.stdout.write("\r" + " " * columns + "\r")
    sys.stdout.flush()


def print_table(results, base, color):
    headers = ["#", "STATUS", "FILE", "SIZE", "NOTE"]
    files = [str(r.path.relative_to(base)) for r in results]
    notes = [r.note for r in results]
    file_width = min(max(len(headers[2]), *map(len, files)), 48)
    note_width = min(max(len(headers[4]), *map(len, notes)), 46)
    widths = [len(str(len(results))), 10, file_width, 10, note_width]

    def rule(left, middle, right):
        return "  " + left + middle.join("─" * (w + 2) for w in widths) + right

    def row(cells, styled=None):
        padded = [cell.ljust(width) for cell, width in zip(cells, widths)]
        if styled is not None:
            padded[1] = paint(padded[1], styled, color)
        return "  │ " + " │ ".join(padded) + " │"

    print(paint("  RESULTS", BOLD, color))
    print(rule("┌", "┬", "┐"))
    print(row(headers))
    print(rule("├", "┼", "┤"))
    for index, (result, name, note) in enumerate(zip(results, files, notes), 1):
        style, icon = STYLES[result.status]
        print(row([
            str(index),
            f"{icon} {result.status}",
            clip(name, file_width),
            human_size(result.size),
            clip(note, note_width),
        ], styled=style))
    print(rule("└", "┴", "┘"))


def print_summary(results, base, color, elapsed, verbose):
    print()
    print_table(results, base, color)
    print()
    counts = {status: sum(r.status == status for r in results) for status in STYLES}
    labels = {"OK": "converted", "REPAIRED": "repaired", "READY": "ready",
              "SKIP": "skipped", "FAIL": "failed"}
    totals = "   ".join(paint(f"{STYLES[s][1]} {counts[s]} {labels[s]}", STYLES[s][0], color)
                        for s in STYLES)
    print(paint("  TOTALS", BOLD, color) + f"   {totals}")
    print(paint(f"  Time: {elapsed:.2f} s", DIM, color))

    failures = [r for r in results if r.status == "FAIL"]
    if failures:
        print()
        print(paint(f"  FAILURES ({len(failures)})", BOLD + STYLES["FAIL"][0], color))
        for r in failures:
            print(f"    ✘ {r.path.relative_to(base)}: {r.note}")

    warnings = [(r, notice) for r in results for notice in r.notices]
    if warnings:
        print()
        print(paint(f"  WARNINGS ({len(warnings)})", BOLD + STYLES["SKIP"][0], color))
        if verbose:
            for r, notice in warnings:
                print(f"    ! {r.path.relative_to(base)}: {notice}")
        else:
            print(paint("    Run with -v to list them.", DIM, color))
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Recursively convert unencrypted, uncompressed SELF *.prx "
                    "(4F 15 3D 1D or 54 14 F5 EE) to ELF, preserving originals "
                    "as *.prxbak / *.binbak. Also processes eboot.bin if present. "
                    "No decryption or decompression is performed. Also repair "
                    "invalid section-table metadata and dangling empty PT_NULL "
                    "headers in existing ELF "
                    "(backup: *.prx.elf.bak).")
    parser.add_argument("path", type=Path, help="directory to scan, or a single .prx/.bin file")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate conversions without modifying files")
    parser.add_argument("--max-output-mib", type=int, default=512,
                        help="maximum reconstructed size per ELF (default: 512 MiB)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="list parser warnings in the summary")
    args = parser.parse_args()
    if args.max_output_mib <= 0:
        parser.error("--max-output-mib must be positive")
    root = args.path.resolve()
    if root.is_dir():
        paths = sorted(path for path in root.rglob("*")
                       if path.suffix.lower() in (".prx", ".bin") and path.is_file())
        base = root
    elif root.is_file() and root.suffix.lower() in (".prx", ".bin"):
        paths = [root]
        base = root.parent
    else:
        parser.error("path must be an existing directory or .prx/.bin file")

    if os.name == "nt":
        os.system("")  # enables ANSI escape handling in Windows consoles
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    interactive = sys.stdout.isatty()

    print_banner(color)
    mode = "dry-run" if args.dry_run else "convert"
    print(f"  {paint('Target', BOLD, color)}  {root}")
    print(f"  {paint('Mode  ', BOLD, color)}  {mode}")
    print(f"  {paint('Files ', BOLD, color)}  {len(paths)} .prx/.bin found")
    print()
    if not paths:
        print("  No .prx/.bin files found.")
        return 0

    max_size = args.max_output_mib * 1024 * 1024
    results = []
    started = time.monotonic()
    for done, path in enumerate(paths, 1):
        if interactive:
            print_progress(done - 1, len(paths), path.name)
        try:
            result = convert_file(path, max_size, args.dry_run)
        except (OSError, ValueError) as error:
            result = Result(path, "FAIL", note=str(error))
        results.append(result)
        if interactive:
            print_progress(done, len(paths), path.name)
    if interactive:
        clear_progress()
    elapsed = time.monotonic() - started

    print_summary(results, base, color, elapsed, args.verbose)
    return 1 if any(r.status == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
