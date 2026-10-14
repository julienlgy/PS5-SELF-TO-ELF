import struct
import tempfile
import unittest
from pathlib import Path

from self_to_elf import (
    SELF_MAGIC,
    convert_file,
    repair_elf_headers,
    self_to_elf,
    validate_elf,
)


def make_elf():
    data = bytearray(256)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH", data, 0,
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 128, 0, 0, 128, 128, 1)
    data[128:] = bytes(range(128))
    return data


def missing_sections(data):
    struct.pack_into("<Q", data, 40, 0x1f849bd8)
    struct.pack_into("<HHH", data, 58, 64, 45, 43)
    return data


class ElfRepairTests(unittest.TestCase):
    def test_missing_section_table_is_rejected_then_repaired(self):
        data = missing_sections(make_elf())
        with self.assertRaisesRegex(ValueError, "section header table.*truncated"):
            validate_elf(data)
        notices = []
        output = repair_elf_headers(data, notices)
        self.assertEqual(output, make_elf())
        self.assertEqual(len(notices), 1)
        self.assertIn("0x1f849bd8", notices[0])
        self.assertEqual(struct.unpack_from("<Q", data, 40)[0], 0x1f849bd8)
        validate_elf(output)
        self.assertIsNone(repair_elf_headers(output))

    def test_valid_section_table_is_preserved(self):
        data = make_elf() + bytearray(192)
        struct.pack_into("<Q", data, 40, 256)
        struct.pack_into("<HHH", data, 58, 64, 2, 1)
        struct.pack_into("<IIQQQQ", data, 256 + 64, 1, 3, 0, 0, 384, 16)
        data[384:400] = b"\x00.shstrtab\x00\x00\x00\x00\x00\x00"
        validate_elf(data)
        self.assertIsNone(repair_elf_headers(data))
        # Extended section count and section-name index use section zero.
        struct.pack_into("<HH", data, 60, 0, 0xffff)
        struct.pack_into("<QI", data, 256 + 32, 2, 1)
        validate_elf(data)
        self.assertIsNone(repair_elf_headers(data))

    def test_truncated_section_payload_or_broken_shstrtab_is_repaired(self):
        # Section table fits in file, but section 2 payload is truncated.
        data = make_elf() + bytearray(256)
        struct.pack_into("<Q", data, 40, 256)
        struct.pack_into("<HHH", data, 58, 64, 3, 1)
        struct.pack_into("<IIQQQQ", data, 256 + 64, 1, 3, 0, 0, 448, 16)
        data[448:464] = b"\x00.shstrtab\x00\x00\x00\x00\x00\x00"
        # Section 2 (SHT_PROGBITS = 1) points outside file (offset 0x9000).
        struct.pack_into("<IIQQQQ", data, 256 + 128, 0, 1, 0, 0, 0x9000, 64)
        notices = []
        output = repair_elf_headers(data, notices)
        self.assertEqual(struct.unpack_from("<Q", output, 40)[0], 0)
        self.assertEqual(output[58:64], bytes(6))
        self.assertEqual(output[64:], data[64:])
        self.assertIn("ELF section 2 at 0x9000 is truncated", notices[0])

        # SHT_NOBITS (8) can have offset/size beyond file without being truncated.
        nobits = make_elf() + bytearray(256)
        struct.pack_into("<Q", nobits, 40, 256)
        struct.pack_into("<HHH", nobits, 58, 64, 3, 1)
        struct.pack_into("<IIQQQQ", nobits, 256 + 64, 1, 3, 0, 0, 448, 16)
        nobits[448:464] = b"\x00.shstrtab\x00\x00\x00\x00\x00\x00"
        struct.pack_into("<IIQQQQ", nobits, 256 + 128, 0, 8, 0, 0, 0x9000, 0x20000)
        validate_elf(nobits)
        self.assertIsNone(repair_elf_headers(nobits))

    def test_dangling_empty_segment_and_dirty_pt_null_are_repaired(self):
        data = make_elf()
        struct.pack_into("<H", data, 56, 3)
        # Program header 1: PT_TLS (7) with filesz=0, memsz=64, offset=0x500000 (> EOF)
        struct.pack_into("<IIQQQQQQ", data, 120, 7, 4, 0x500000, 0x2000, 0x2000, 0, 64, 8)
        # Program header 2: PT_NULL (0) with residual non-zero fields
        struct.pack_into("<IIQQQQQQ", data, 176, 0, 4, 128, 0x1000, 0, 0, 32, 4)
        with self.assertRaisesRegex(ValueError, "payload outside file"):
            validate_elf(data)
        notices = []
        output = repair_elf_headers(data, notices)
        self.assertEqual(
            struct.unpack_from("<IIQQQQQQ", output, 120),
            (7, 4, 0, 0x2000, 0x2000, 0, 64, 8),
        )
        self.assertEqual(output[176:232], bytes(56))
        self.assertEqual(len(notices), 2)
        validate_elf(output)

    def test_truncated_optional_metadata_segment_is_stripped(self):
        for kind in (0x6fffff00, 0x6fffff01, 4):
            with self.subTest(kind=hex(kind)):
                data = make_elf()
                struct.pack_into("<H", data, 56, 2)
                struct.pack_into("<IIQQQQQQ", data, 120, kind, 0, 0x40000, 0, 0, 0x80, 0, 4)
                notices = []
                output = repair_elf_headers(data, notices)
                self.assertEqual(output[120:176], bytes(56))
                self.assertEqual(len(notices), 1)
                validate_elf(output)
        # A loadable PT_NOTE (address != 0 or memsz != 0) is runtime metadata and must NOT be stripped.
        runtime_note = make_elf()
        struct.pack_into("<H", runtime_note, 56, 2)
        struct.pack_into("<IIQQQQQQ", runtime_note, 120, 4, 4, 0x40000, 0x1000, 0x1000, 0x24, 0x24, 4)
        self.assertIsNone(repair_elf_headers(runtime_note))
        with self.assertRaisesRegex(ValueError, "payload outside file"):
            validate_elf(runtime_note)

    def test_partial_table_and_inconsistent_metadata(self):
        for offset, entry_size, count, names in [
            (240, 64, 1, 0), (192, 64, 2, 0),
            (0, 64, 1, 0), (0, 0, 0, 1),
            (192, 32, 1, 0), (192, 64, 1, 2),
        ]:
            with self.subTest(offset=offset, count=count, names=names):
                data = make_elf()
                struct.pack_into("<Q", data, 40, offset)
                struct.pack_into("<HHH", data, 58, entry_size, count, names)
                self.assertEqual(repair_elf_headers(data), make_elf())

    def test_runtime_corruption_is_not_hidden(self):
        data = missing_sections(make_elf())
        struct.pack_into("<Q", data, 64 + 32, 129)
        with self.assertRaisesRegex(ValueError, "payload outside file"):
            repair_elf_headers(data)

    def test_null_and_section_repairs_can_be_combined(self):
        data = make_elf()
        struct.pack_into("<H", data, 56, 2)
        struct.pack_into("<IIQQQQQQ", data, 120, 0, 0, 10000, 0, 0, 0, 0, 0)
        missing_sections(data)
        output = repair_elf_headers(data)
        self.assertEqual(output[120:176], bytes(56))
        self.assertEqual(output[176:], data[176:])
        validate_elf(output)

    def test_conversion_still_strips_missing_sections(self):
        elf = missing_sections(make_elf())
        data = bytearray(384)
        data[:12] = SELF_MAGIC + bytes.fromhex("0001011201010000")
        struct.pack_into("<HHQH", data, 12, 256, 0, len(data), 1)
        struct.pack_into("<QQQQ", data, 32, 4, 256, 128, 128)
        data[64:184] = elf[:120]
        data[256:] = elf[128:]
        output = self_to_elf(data)
        validate_elf(output)
        self.assertEqual(output[128:], elf[128:])
        self.assertEqual(struct.unpack_from("<Q", output, 40)[0], 0)
        self.assertEqual(output[58:64], bytes(6))

    def test_file_repair_backup_dry_run_and_repeat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.prx"
            data = missing_sections(make_elf())
            path.write_bytes(data)
            backup = path.with_name(path.name + ".elf.bak")
            result = convert_file(path, 512 * 1024 * 1024, True)
            self.assertEqual(result.status, "READY")
            self.assertEqual(path.read_bytes(), data)
            self.assertFalse(backup.exists())
            result = convert_file(path, 512 * 1024 * 1024, False)
            self.assertEqual(result.status, "REPAIRED")
            self.assertEqual(backup.read_bytes(), data)
            self.assertEqual(path.read_bytes(), make_elf())
            self.assertEqual(convert_file(path, 512 * 1024 * 1024, False).status, "SKIP")

    def test_invalid_existing_elf_fails_instead_of_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.prx"
            data = make_elf()
            struct.pack_into("<Q", data, 64 + 32, 129)
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "payload outside file"):
                convert_file(path, 512 * 1024 * 1024, False)
            self.assertEqual(path.read_bytes(), data)
            self.assertFalse(path.with_name(path.name + ".elf.bak").exists())

    def test_existing_backup_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.prx"
            data = missing_sections(make_elf())
            path.write_bytes(data)
            backup = path.with_name(path.name + ".elf.bak")
            backup.write_bytes(b"original backup")
            with self.assertRaisesRegex(ValueError, "backup already exists"):
                convert_file(path, 512 * 1024 * 1024, False)
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(backup.read_bytes(), b"original backup")

    def test_windows_dll_is_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.prx"
            data = b"MZ" + bytes(254)
            path.write_bytes(data)
            self.assertEqual(convert_file(path, 512 * 1024 * 1024, False).status, "SKIP")
            self.assertEqual(path.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
