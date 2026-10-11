"""Per-file conversion, atomic replacement with backup, and decryption status."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import struct
import tempfile

from .checks import require
from .constants import ELF_MAGIC, SELF_MAGICS
from .elf import repair_empty_null_headers
from .formats import describe_format
from .self_parser import self_to_elf


@dataclass
class Result:
    path: Path
    status: str
    size: int = 0
    note: str = ""
    notices: list = field(default_factory=list)


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
        output = repair_empty_null_headers(data)
        if output is None:
            return Result(path, "SKIP", note=describe_format(header))
        backup = path.with_name(path.name + ".elf.bak")
        status = "REPAIRED"
    else:
        output = self_to_elf(data, max_size, notices)
        backup = path.with_name(path.name + ".bak")
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


def check_full_decryption(paths):
    """Check if all SELF files were successfully converted (no encrypted/compressed segments)."""
    checked = 0
    for path in paths:
        if path.suffix.lower() not in (".prx", ".bin"):
            continue
        try:
            with path.open("rb") as stream:
                header = stream.read(64)
                magic = header[:4]
                if magic in SELF_MAGICS:
                    stream.seek(0)
                    data = stream.read()
                    # Check if it's a valid SELF that could be converted
                    if data[:4] in SELF_MAGICS and data[4:12] == bytes.fromhex("0001011201010000"):
                        checked += 1
                        # Try to parse entries to see if any are encrypted/compressed
                        entry_count, = struct.unpack_from("<H", data, 24)
                        for i in range(entry_count):
                            flags, _, _, _ = struct.unpack_from("<QQQQ", data, 32 + i * 32)
                            if flags & 2:  # encrypted
                                return False, f"{path.name}: contains encrypted segments"
                            if flags & 8:  # compressed
                                return False, f"{path.name}: contains compressed segments"
        except Exception:
            pass
    if not checked:
        return False, "no SELF files found to decrypt"
    return True, "All SELF files fully decrypted and converted"
