import io
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from self_to_elf import (
    SELF_MAGIC,
    SELF_MAGICS,
    convert_file,
    describe_format,
    human_size,
    main,
    repair_elf_headers,
    self_to_elf,
    validate_elf,
)


def make_elf(phdrs=None, e_type=3):
    if phdrs is None:
        phdrs = [(1, 5, 128, 0, 0, 128, 128, 1)]
    ph_offset = 64
    ph_count = len(phdrs)
    end = max(
        [ph_offset + ph_count * 56]
        + [offset + size for _, _, offset, _, _, size, _, _ in phdrs if size > 0]
    )
    data = bytearray(end)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH", data, 0,
        b"\x7fELF\x02\x01\x01" + bytes(9),
        e_type, 62, 1, 0, ph_offset, 0, 0, 64, 56, ph_count, 0, 0, 0,
    )
    for i, phdr in enumerate(phdrs):
        struct.pack_into("<IIQQQQQQ", data, ph_offset + i * 56, *phdr)
    if phdrs == [(1, 5, 128, 0, 0, 128, 128, 1)]:
        data[128:] = bytes(range(128))
    else:
        for _, _, offset, _, _, size, _, _ in phdrs:
            for pos in range(offset, offset + size):
                if pos >= ph_offset + ph_count * 56:
                    data[pos] = (pos * 31 + 7) & 0xff
    return data


def build_self(elf, entries_spec, magic=SELF_MAGIC, metadata_size=0,
               self_size_override=None, trailer=b""):
    entry_count = len(entries_spec)
    elf_offset = 32 + entry_count * 32
    ph_offset, = struct.unpack_from("<Q", elf, 32)
    ph_size, ph_count = struct.unpack_from("<HH", elf, 54)
    elf_header_size = ph_offset + ph_count * ph_size
    header_size = (elf_offset + elf_header_size + 15) & ~15
    payload_start = header_size + metadata_size

    cursor = payload_start
    entries = []
    payload_chunks = []
    for flags, payload, source_override, stored_override, unpacked_override in entries_spec:
        if payload is None:
            source = 0 if source_override is None else source_override
            stored = 0 if stored_override is None else stored_override
            unpacked = 0 if unpacked_override is None else unpacked_override
        else:
            source = cursor if source_override is None else source_override
            stored = len(payload) if stored_override is None else stored_override
            unpacked = len(payload) if unpacked_override is None else unpacked_override
            payload_chunks.append((source, payload))
            cursor = max(cursor, source + len(payload))
        entries.append((flags, source, stored, unpacked))

    self_size = cursor if self_size_override is None else self_size_override
    total_len = max(cursor, self_size if not trailer else self_size + len(trailer))
    if self_size_override is not None and not trailer and self_size_override > cursor:
        total_len = cursor
    data = bytearray(max(payload_start, total_len))
    data[:12] = magic + bytes.fromhex("0001011201010000")
    struct.pack_into("<HHQH", data, 12, header_size, metadata_size, self_size, entry_count)
    for i, entry in enumerate(entries):
        struct.pack_into("<QQQQ", data, 32 + i * 32, *entry)
    data[elf_offset:elf_offset + elf_header_size] = elf[:elf_header_size]
    for source, payload in payload_chunks:
        if source + len(payload) > len(data):
            data.extend(bytes(source + len(payload) - len(data)))
        data[source:source + len(payload)] = payload
    if trailer:
        if len(data) < self_size:
            data.extend(bytes(self_size - len(data)))
        data[self_size:self_size + len(trailer)] = trailer
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
        self.assertIn("MZ executable", describe_format(b"MZ" + bytes(30)))
        self.assertIn("PSP ~PSP", describe_format(b"~PSP" + bytes(30)))
        self.assertIn("PSP PELF", describe_format(b"PELF\x01\x01" + bytes(12) + struct.pack("<H", 8)))
        self.assertIn("empty file", describe_format(b""))
        self.assertEqual(human_size(0), "-")
        self.assertEqual(human_size(512), "512 B")
        self.assertEqual(human_size(2048), "2.0 KiB")
        self.assertEqual(human_size(2 * 1024 ** 3), "2.0 GiB")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.prx"
            data = b"MZ" + bytes(254)
            path.write_bytes(data)
            self.assertEqual(convert_file(path, 512 * 1024 * 1024, False).status, "SKIP")
            self.assertEqual(path.read_bytes(), data)


class SelfConversionTests(unittest.TestCase):
    def test_both_self_magics_and_complex_ps5_segments_convert_perfectly(self):
        phdrs = [
            (6, 4, 64, 0x40, 0x40, 10 * 56, 10 * 56, 8),               # 0: PT_PHDR
            (1, 5, 0x400, 0x400, 0x400, 0x200, 0x200, 0x400),          # 1: PT_LOAD (RX)
            (1, 4, 0x800, 0x800, 0x800, 0x200, 0x200, 0x400),          # 2: PT_LOAD (RO)
            (0x61000001, 4, 0x840, 0x840, 0x840, 0x40, 0x40, 8),       # 3: PT_SCE_PROCPARAM (covered by 2)
            (0x6474e550, 4, 0x880, 0x880, 0x880, 0x40, 0x40, 4),       # 4: PT_GNU_EH_FRAME (covered by 2)
            (0x61000010, 4, 0xc00, 0xc00, 0xc00, 0x100, 0x100, 0x400), # 5: PT_SCE_RELRO
            (1, 6, 0x1000, 0x1000, 0x1000, 0x180, 0x400, 0x400),       # 6: PT_LOAD (RW + BSS)
            (7, 4, 0x1000, 0x1000, 0x1000, 0x40, 0x80, 16),            # 7: PT_TLS (covered by 6)
            (2, 6, 0x1240, 0, 0, 0x80, 0, 8),                          # 8: PT_DYNAMIC (covered by 9)
            (0x61000000, 0, 0x1200, 0, 0, 0x200, 0, 16),               # 9: PT_SCE_DYNLIBDATA
        ]
        elf = missing_sections(make_elf(phdrs, e_type=0xfe10))
        entries_spec = [
            ((1 << 20) | 0x10005, bytes(64), None, None, None),
            ((1 << 20) | 0x4805, elf[0x400:0x600], None, None, None),
            ((2 << 20) | 0x30004, bytes(32), None, None, None),
            ((2 << 20) | 0x4804, elf[0x800:0xa00], None, None, None),
            ((5 << 20) | 0x4800, elf[0xc00:0xd00], None, None, None),
            ((6 << 20) | 0x0004, elf[0x1000:0x1180], None, None, None),
            ((9 << 20) | 0x10004, bytes(32), None, None, None),
            ((9 << 20) | 0x0001, elf[0x1200:0x1400], None, None, None),
        ]
        for magic in SELF_MAGICS:
            raw_self = build_self(elf, entries_spec, magic=magic, metadata_size=64)
            output = self_to_elf(raw_self)
            validate_elf(output)
            self.assertEqual(output[0x400:0x600], elf[0x400:0x600])
            self.assertEqual(output[0x800:0xa00], elf[0x800:0xa00])
            self.assertEqual(output[0xc00:0xd00], elf[0xc00:0xd00])
            self.assertEqual(output[0x1000:0x1180], elf[0x1000:0x1180])
            self.assertEqual(output[0x1200:0x1400], elf[0x1200:0x1400])

    def test_pt_load_starting_at_offset_zero_and_nested_segments(self):
        phdrs = [
            (1, 5, 0, 0x400000, 0x400000, 0x200, 0x200, 0x1000),
        ]
        elf = make_elf(phdrs, e_type=2)
        raw_self = build_self(elf, [((0 << 20) | 4, bytes(elf), None, None, None)])
        output = self_to_elf(raw_self)
        validate_elf(output)
        self.assertEqual(output, elf)

        phdrs_nested = [
            (1, 5, 0, 0x400000, 0x400000, 0x200, 0x200, 0x1000),
            (2, 6, 0x240, 0, 0, 0x80, 0, 8),
            (0x61000000, 0, 0x200, 0, 0, 0x100, 0, 16),
            (0, 0, 0x999999, 0x1234, 0, 0, 0x5678, 0),
        ]
        elf_nested = make_elf(phdrs_nested, e_type=2)
        nested_self = build_self(elf_nested, [
            ((0 << 20) | 4, bytes(elf_nested[:0x200]), None, None, None),
            ((1 << 20) | 4, bytes(elf_nested[0x240:0x2c0]), None, None, None),
            ((2 << 20) | 4, bytes(elf_nested[0x200:0x300]), None, None, None),
        ])
        out_nested = self_to_elf(nested_self)
        validate_elf(out_nested)
        self.assertEqual(len(out_nested), 0x300)
        self.assertEqual(out_nested[64 + 3 * 56:64 + 4 * 56], bytes(56))

        bad_payload = bytearray(elf)
        bad_payload[64] ^= 0xff
        bad_self = build_self(elf, [((0 << 20) | 4, bad_payload, None, None, None)])
        with self.assertRaisesRegex(ValueError, "overlapping ELF payload"):
            self_to_elf(bad_self)

    def test_empty_bss_pt_load_preserves_congruent_offset(self):
        phdrs = [
            (1, 5, 0x200, 0x200, 0x200, 0x200, 0x200, 0x4000),
            (1, 6, 0x4200, 0x8200, 0x8200, 0, 0x1000, 0x4000),
            (0x6474e551, 6, 0x99999, 0, 0, 0, 0, 8),
        ]
        elf = make_elf(phdrs)
        entries_spec = [
            ((0 << 20) | 4, elf[0x200:0x400], None, None, None),
            ((1 << 20) | 4, None, 0, 0, 0),
        ]
        raw_self = build_self(elf, entries_spec)
        output = self_to_elf(raw_self)
        validate_elf(output)
        self.assertEqual(len(output), 0x4200)
        self.assertEqual(struct.unpack_from("<Q", output, 64 + 56 + 8)[0], 0x4200)
        self.assertEqual(struct.unpack_from("<Q", output, 64 + 112 + 8)[0], 0)

    def test_missing_final_alignment_padding_accepted_only_when_payload_complete(self):
        elf = make_elf([(1, 5, 128, 0, 0, 128, 128, 1)])
        raw_self = build_self(
            elf,
            [((0 << 20) | 4, elf[128:256], 248, 128, 128)],
            self_size_override=384,
        )
        self.assertEqual(len(raw_self), 376)
        notices = []
        output = self_to_elf(raw_self, notices=notices)
        self.assertEqual(output, elf)
        self.assertEqual(notices, ["accepted missing final SELF alignment padding (8 bytes)"])
        with self.assertRaisesRegex(ValueError, "payload outside SELF"):
            self_to_elf(raw_self[:-1])

    def test_unsigned_trailers_complete_contiguous_truncated_and_zero_padding(self):
        comment_bytes = b"SCE_COMMENT_PAYLOAD_DATA"
        libver_bytes = b"SCE_LIBVER_DATA!"
        phdrs = [
            (1, 5, 256, 0, 0, 128, 128, 1),
            (0x6fffff00, 0, 384, 0, 0, len(comment_bytes), 0, 1),
            (0x6fffff01, 0, 384 + len(comment_bytes), 0, 0, len(libver_bytes), 0, 1),
        ]
        elf = make_elf(phdrs)
        both_self = build_self(
            elf,
            [((0 << 20) | 4, elf[256:384], None, None, None)],
            trailer=comment_bytes + libver_bytes,
        )
        out_both = self_to_elf(both_self)
        validate_elf(out_both)
        self.assertEqual(out_both[384:384 + len(comment_bytes)], comment_bytes)
        self.assertEqual(out_both[384 + len(comment_bytes):], libver_bytes)

        phdrs_single = [
            (1, 5, 256, 0, 0, 128, 128, 1),
            (0x6fffff00, 0, 384, 0, 0, len(comment_bytes), 0, 1),
        ]
        elf_single = make_elf(phdrs_single)
        trunc_self = build_self(
            elf_single,
            [((0 << 20) | 4, elf_single[256:384], None, None, None)],
            trailer=comment_bytes[:10],
        )
        notices = []
        out_trunc = self_to_elf(trunc_self, notices=notices)
        validate_elf(out_trunc)
        self.assertEqual(out_trunc[64 + 56:64 + 112], bytes(56))
        self.assertIn("stripped incomplete SCE COMMENT (10/24 bytes)", notices[0])

        elf_basic = make_elf([(1, 5, 128, 0, 0, 128, 128, 1)])
        unaligned_self = build_self(
            elf_basic,
            [((0 << 20) | 4, elf_basic[128:256], 196, 128, 128)],
            self_size_override=324,
            trailer=bytes(12),
        )
        notices_pad = []
        out_pad = self_to_elf(unaligned_self, notices=notices_pad)
        self.assertEqual(out_pad, elf_basic)
        self.assertEqual(notices_pad, ["ignored trailing SELF alignment padding (12 bytes)"])

    def test_rejects_encrypted_compressed_and_malformed_self_inputs(self):
        elf = make_elf()
        enc_self = build_self(elf, [((0 << 20) | 6, elf[128:], None, None, None)])
        with self.assertRaisesRegex(ValueError, "encrypted; no decryption is performed"):
            self_to_elf(enc_self)

        comp_self = build_self(elf, [((0 << 20) | 12, elf[128:], None, None, None)])
        with self.assertRaisesRegex(ValueError, "compressed; provide an uncompressed SELF"):
            self_to_elf(comp_self)

        for bad_flags in [(0 << 20) | 0x1004, (0 << 20) | 0x14, (1 << 32) | 4, (0 << 20) | 0x10804]:
            bad = build_self(elf, [(bad_flags, elf[128:], None, None, None)])
            with self.assertRaisesRegex(ValueError, "unsupported flags"):
                self_to_elf(bad)

        phdrs = [
            (1, 5, 256, 0, 0, 128, 128, 1),
            (1, 6, 384, 0x1000, 0x1000, 128, 128, 1),
        ]
        elf2 = make_elf(phdrs)
        missing_load = build_self(elf2, [((0 << 20) | 4, elf2[256:384], None, None, None)])
        with self.assertRaisesRegex(ValueError, "missing payload for program header 1"):
            self_to_elf(missing_load)

    def test_cli_end_to_end_directory_and_single_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = make_elf()
            raw_self = build_self(elf, [((0 << 20) | 4, elf[128:], None, None, None)])
            eboot = root / "eboot.bin"
            prx = root / "lib.prx"
            eboot.write_bytes(raw_self)
            prx.write_bytes(missing_sections(make_elf()))

            buf = io.StringIO()
            with mock.patch.object(sys, "argv", ["self_to_elf.py", str(root), "-v"]), redirect_stdout(buf):
                code = main()
            self.assertEqual(code, 0)
            self.assertEqual(eboot.read_bytes(), elf)
            self.assertTrue((root / "eboot.binbak").exists())
            self.assertEqual(prx.read_bytes(), elf)
            self.assertTrue((root / "lib.prx.elf.bak").exists())
            self.assertIn("TOTALS", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
