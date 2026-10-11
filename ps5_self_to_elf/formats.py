"""Human-readable format detection from a file header."""

import struct

from .constants import ELF_MAGIC, SELF_MAGICS


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
