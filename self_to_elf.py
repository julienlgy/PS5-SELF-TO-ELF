#!/usr/bin/env python3
"""Convert raw SELF PRX files in place, preserving originals as .prx.bak.

Thin entry point; the implementation lives in the ``ps5_self_to_elf`` package.
"""

import sys

from ps5_self_to_elf.checks import require
from ps5_self_to_elf.cli import main
from ps5_self_to_elf.constants import DEFAULT_MAX_SIZE, ELF_MAGIC, SELF_MAGIC, SELF_MAGICS
from ps5_self_to_elf.converter import Result, check_full_decryption, convert_file
from ps5_self_to_elf.elf import repair_empty_null_headers, validate_elf
from ps5_self_to_elf.formats import describe_format
from ps5_self_to_elf.self_parser import self_to_elf

__all__ = [
    "DEFAULT_MAX_SIZE", "ELF_MAGIC", "SELF_MAGIC", "SELF_MAGICS",
    "Result", "check_full_decryption", "convert_file", "describe_format",
    "main", "repair_empty_null_headers", "require", "self_to_elf", "validate_elf",
]


if __name__ == "__main__":
    sys.exit(main())
