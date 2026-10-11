"""Command-line entry point: argument parsing and the conversion run."""

import argparse
import os
from pathlib import Path
import sys
import time

from .converter import Result, check_full_decryption, convert_file
from .report import BOLD, clear_progress, paint, print_banner, print_progress, print_summary


def main():
    parser = argparse.ArgumentParser(
        description="Recursively convert unencrypted, uncompressed SELF *.prx "
                    "(4F 15 3D 1D or 54 14 F5 EE) to ELF, preserving originals "
                    "as *.prx.bak. Also processes eboot.bin if present. "
                    "No decryption or decompression is performed. Also repair "
                    "dangling empty PT_NULL headers in previously converted ELF "
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
    fully_decrypted, decryption_msg = check_full_decryption(paths)
    print(f"Decryption status: {'OK - Full decryption' if fully_decrypted else 'PARTIAL - ' + decryption_msg}")
    return 1 if any(r.status == "FAIL" for r in results) else 0
