"""ELF64 x86-64 validation and repair of previously converted files."""

import struct

from .checks import fits, overlaps, require
from .constants import ELF_MAGIC


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
