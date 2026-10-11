"""SELF container parsing and reconstruction of the ELF image."""

import struct

from .checks import covered, fits, overlaps, require
from .constants import DEFAULT_MAX_SIZE, ELF_MAGIC, SELF_MAGICS
from .elf import validate_elf


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
