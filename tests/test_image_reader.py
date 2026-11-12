"""
Unit Tests for Read-Only Forensic Image Reader & Partition Enumerator
Department 1: Cyber Triage & Evidence Ingestion (SIH1744 / NIA Specification)
"""

import os
import struct
import tempfile
import uuid
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.core.image_reader import (
    EWF_MAGIC_E01,
    EWF_MAGIC_EX01,
    EWF_MAGIC_L01,
    GPT_HEADER_SIGNATURE,
    MBR_BOOT_SIGNATURE,
    EWFImgInfo,
    ForensicImageReader,
    ImageMetadata,
    PartitionInfo,
    detect_filesystem_signature,
    detect_image_format,
)


# ---------------------------------------------------------------------------
# Synthetic Test Image Generators
# ---------------------------------------------------------------------------
def create_synthetic_mbr_image(tmp_path: Path, sector_size: int = 512, total_sectors: int = 200) -> Path:
    """Creates a synthetic raw disk image with a valid 2-partition MBR table."""
    disk_data = bytearray(total_sectors * sector_size)

    # Partition 1: Bootable, NTFS, Start LBA 4, Count 50
    p1 = struct.pack("<B3sB3sII", 0x80, b"\x00\x01\x00", 0x07, b"\x00\x02\x00", 4, 50)
    # Partition 2: Non-bootable, Linux Native, Start LBA 60, Count 40
    p2 = struct.pack("<B3sB3sII", 0x00, b"\x00\x01\x00", 0x83, b"\x00\x02\x00", 60, 40)

    disk_data[446:446 + 16] = p1
    disk_data[462:462 + 16] = p2
    disk_data[510:512] = MBR_BOOT_SIGNATURE

    # Plant NTFS OEM signature in Partition 1 boot sector if image is large enough
    if total_sectors >= 5:
        disk_data[4 * sector_size:4 * sector_size + 11] = b"\xeb\x52\x90NTFS    "

    # Plant ext4 superblock magic (0xEF53) in Partition 2 superblock if image is large enough
    if total_sectors >= 63:
        disk_data[60 * sector_size + 1080:60 * sector_size + 1082] = b"\x53\xef"

    img_path = tmp_path / "test_mbr.raw"
    img_path.write_bytes(disk_data)
    return img_path


def create_synthetic_gpt_image(tmp_path: Path, sector_size: int = 512, total_sectors: int = 200) -> Path:
    """Creates a synthetic raw disk image with a valid Protective MBR and GPT table."""
    disk_data = bytearray(total_sectors * sector_size)

    # 1. Protective MBR at LBA 0
    p_mbr = struct.pack("<B3sB3sII", 0x00, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1, total_sectors - 1)
    disk_data[446:446 + 16] = p_mbr
    disk_data[510:512] = MBR_BOOT_SIGNATURE

    # 2. Partition Entries at LBA 2 (Sectors 2..33)
    # Entry 0: Windows Basic Data (NTFS)
    type_guid_win = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").bytes_le
    part_guid_win = uuid.uuid4().bytes_le
    win_start_lba = 34
    win_end_lba = 80
    win_name = "Windows_Evidence".encode("utf-16le").ljust(72, b"\x00")
    entry0 = struct.pack("<16s16sQQQ72s", type_guid_win, part_guid_win, win_start_lba, win_end_lba, 0, win_name)

    # Entry 1: Linux Filesystem Data
    type_guid_linux = uuid.UUID("0FC63DAF-8483-4772-8E79-3D69D8477DE4").bytes_le
    part_guid_linux = uuid.uuid4().bytes_le
    linux_start_lba = 90
    linux_end_lba = 150
    linux_name = "Linux_Root".encode("utf-16le").ljust(72, b"\x00")
    entry1 = struct.pack("<16s16sQQQ72s", type_guid_linux, part_guid_linux, linux_start_lba, linux_end_lba, 0, linux_name)

    entries = bytearray(128 * 128)
    entries[0:128] = entry0
    entries[128:256] = entry1
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF

    # 3. GPT Header at LBA 1
    disk_guid = uuid.uuid4().bytes_le
    header_fmt = "<8sIIIIQQQQ16sQIII"
    header_no_crc = struct.pack(
        header_fmt,
        GPT_HEADER_SIGNATURE,
        0x00010000,
        92,
        0,  # CRC placeholder
        0,
        1,  # current LBA
        total_sectors - 1,
        34,  # first usable
        total_sectors - 34,
        disk_guid,
        2,  # partition entries LBA
        128,  # num entries
        128,  # entry size
        entries_crc,
    )
    header_crc = zlib.crc32(header_no_crc) & 0xFFFFFFFF
    header = struct.pack(
        header_fmt,
        GPT_HEADER_SIGNATURE,
        0x00010000,
        92,
        header_crc,
        0,
        1,
        total_sectors - 1,
        34,
        total_sectors - 34,
        disk_guid,
        2,
        128,
        128,
        entries_crc,
    )

    disk_data[1 * sector_size:1 * sector_size + 92] = header
    disk_data[2 * sector_size:2 * sector_size + len(entries)] = entries

    # Plant filesystem signatures
    # NTFS at sector 34
    disk_data[win_start_lba * sector_size:win_start_lba * sector_size + 11] = b"\xeb\x52\x90NTFS    "
    # Ext4 at sector 90
    disk_data[linux_start_lba * sector_size + 1080:linux_start_lba * sector_size + 1082] = b"\x53\xef"

    img_path = tmp_path / "test_gpt.raw"
    img_path.write_bytes(disk_data)
    return img_path


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------
class TestMagicByteInspection:
    """Verifies magic byte detection for forensic containers and partition systems."""

    def test_detect_ewf_magic_e01(self):
        sample = EWF_MAGIC_E01 + b"\x00" * 1024
        assert detect_image_format(sample) == "E01"

    def test_detect_ewf_magic_l01(self):
        sample = EWF_MAGIC_L01 + b"\x00" * 1024
        assert detect_image_format(sample) == "E01"

    def test_detect_ewf_magic_ex01(self):
        sample = EWF_MAGIC_EX01 + b"\x00" * 1024
        assert detect_image_format(sample) == "Ex01"

    def test_detect_gpt_magic(self):
        sample = bytearray(1024)
        sample[512:520] = GPT_HEADER_SIGNATURE
        assert detect_image_format(bytes(sample)) == "GPT_RAW"

    def test_detect_mbr_magic(self):
        sample = bytearray(1024)
        sample[510:512] = MBR_BOOT_SIGNATURE
        assert detect_image_format(bytes(sample)) == "MBR_RAW"

    def test_detect_plain_raw(self):
        sample = b"\x00" * 1024
        assert detect_image_format(sample) == "RAW"


class TestFilesystemSignatures:
    """Verifies filesystem boot sector and superblock signature probing."""

    def test_ntfs_detection(self):
        buf = bytearray(2048)
        buf[3:11] = b"NTFS    "
        assert detect_filesystem_signature(lambda off, sz: bytes(buf[off:off + sz]), 0, 2048) == "NTFS"

    def test_fat32_detection(self):
        buf = bytearray(2048)
        buf[82:90] = b"FAT32   "
        assert detect_filesystem_signature(lambda off, sz: bytes(buf[off:off + sz]), 0, 2048) == "FAT32"

    def test_ext4_detection(self):
        buf = bytearray(2048)
        buf[1080:1082] = b"\x53\xef"
        assert detect_filesystem_signature(lambda off, sz: bytes(buf[off:off + sz]), 0, 2048) == "EXT4"

    def test_exfat_detection(self):
        buf = bytearray(2048)
        buf[3:11] = b"EXFAT   "
        assert detect_filesystem_signature(lambda off, sz: bytes(buf[off:off + sz]), 0, 2048) == "exFAT"

    def test_apfs_detection(self):
        buf = bytearray(2048)
        buf[0:4] = b"NXSB"
        assert detect_filesystem_signature(lambda off, sz: bytes(buf[off:off + sz]), 0, 2048) == "APFS"


class TestMBRPartitionTable:
    """Verifies MBR partition table parsing across pytsk3 and native fallback modes."""

    def test_mbr_enumeration_both_parsers(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path)

        with ForensicImageReader(img_path) as reader:
            assert reader.is_open
            meta = reader.get_metadata()
            assert meta.size_bytes == 200 * 512
            assert meta.format_type in ("MBR_RAW", "RAW")

            # 1. Native pure-Python fallback enumeration
            native_parts = reader.enumerate_partitions(allocated_only=True, force_native=True)
            assert len(native_parts) == 2

            p1 = native_parts[0]
            assert p1.slot == 0
            assert p1.start_sector == 4
            assert p1.byte_offset == 4 * 512
            assert p1.size_bytes == 50 * 512
            assert p1.filesystem_type == "NTFS"
            assert p1.is_allocated is True
            assert p1.partition_type_id == 0x07

            p2 = native_parts[1]
            assert p2.slot == 1
            assert p2.start_sector == 60
            assert p2.byte_offset == 60 * 512
            assert p2.size_bytes == 40 * 512
            assert p2.filesystem_type == "EXT4"
            assert p2.is_allocated is True
            assert p2.partition_type_id == 0x83

            # 2. Pytsk3 enumeration (if installed)
            tsk_parts = reader.enumerate_partitions(allocated_only=True, force_native=False)
            assert len(tsk_parts) == 2
            assert tsk_parts[0].start_sector == 4
            assert tsk_parts[0].size_bytes == 50 * 512
            assert tsk_parts[0].filesystem_type == "NTFS"
            assert tsk_parts[1].start_sector == 60
            assert tsk_parts[1].size_bytes == 40 * 512
            assert tsk_parts[1].filesystem_type == "EXT4"

    def test_mbr_unallocated_gaps(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path)
        with ForensicImageReader(img_path) as reader:
            parts = reader.enumerate_partitions(allocated_only=False, force_native=True)
            # Should have: gap [0..4), p1 [4..54), gap [54..60), p2 [60..100), tail gap [100..200)
            unalloc = [p for p in parts if not p.is_allocated]
            assert len(unalloc) == 3
            assert unalloc[0].start_sector == 0
            assert unalloc[0].size_bytes == 4 * 512
            assert unalloc[1].start_sector == 54
            assert unalloc[1].size_bytes == 6 * 512
            assert unalloc[2].start_sector == 100
            assert unalloc[2].size_bytes == 100 * 512


class TestGPTPartitionTable:
    """Verifies GPT partition table parsing, UUID handling, and UTF-16 labels."""

    def test_gpt_enumeration_both_parsers(self, tmp_path):
        img_path = create_synthetic_gpt_image(tmp_path)

        with ForensicImageReader(img_path) as reader:
            assert reader.is_open
            meta = reader.get_metadata()
            assert meta.format_type == "GPT_RAW"

            # 1. Native pure-Python fallback enumeration
            native_parts = reader.enumerate_partitions(allocated_only=True, force_native=True)
            assert len(native_parts) == 2

            p0 = native_parts[0]
            assert p0.slot == 0
            assert p0.description == "Windows_Evidence"
            assert p0.filesystem_type == "NTFS"
            assert p0.start_sector == 34
            assert p0.byte_offset == 34 * 512
            assert p0.size_bytes == (80 - 34 + 1) * 512
            assert p0.is_allocated is True
            assert p0.partition_type_guid == "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"

            p1 = native_parts[1]
            assert p1.slot == 1
            assert p1.description == "Linux_Root"
            assert p1.filesystem_type == "EXT4"
            assert p1.start_sector == 90
            assert p1.byte_offset == 90 * 512
            assert p1.size_bytes == (150 - 90 + 1) * 512
            assert p1.is_allocated is True
            assert p1.partition_type_guid == "0FC63DAF-8483-4772-8E79-3D69D8477DE4"

            # 2. Pytsk3 enumeration
            tsk_parts = reader.enumerate_partitions(allocated_only=True, force_native=False)
            assert len(tsk_parts) == 2
            assert tsk_parts[0].description == "Windows_Evidence"
            assert tsk_parts[0].start_sector == 34
            assert tsk_parts[0].size_bytes == (80 - 34 + 1) * 512
            assert tsk_parts[1].description == "Linux_Root"
            assert tsk_parts[1].start_sector == 90
            assert tsk_parts[1].size_bytes == (150 - 90 + 1) * 512


class TestReadOnlyEnforcementAndSafety:
    """Verifies strict read-only guarantees, permission checks, and boundaries."""

    def test_write_operation_raises_permission_error(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path)
        with ForensicImageReader(img_path) as reader:
            with pytest.raises(PermissionError, match="strictly read-only"):
                reader.write(b"tampering_attempt")

    def test_read_boundary_and_validation(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path, total_sectors=10)
        with ForensicImageReader(img_path) as reader:
            # Valid read
            data = reader.read(0, 512)
            assert len(data) == 512

            # Zero size read
            assert reader.read(10, 0) == b""

            # Clamped read past end of file
            data_tail = reader.read(9 * 512, 1024)
            assert len(data_tail) == 512  # Clamped to remaining 1 sector

            # Offset beyond EOF
            assert reader.read(100 * 512, 100) == b""

            # Invalid negative offset/size
            with pytest.raises(ValueError):
                reader.read(-1, 100)
            with pytest.raises(ValueError):
                reader.read(0, -5)


class TestContextManagerAndTeardown:
    """Verifies clean context manager protocol and idempotent closing."""

    def test_clean_close_and_subsequent_read_failure(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path)
        reader = ForensicImageReader(img_path)
        with reader as img:
            assert img.is_open
            data = img.read(0, 16)
            assert len(data) == 16

        assert not reader.is_open
        with pytest.raises(ValueError, match="closed"):
            reader.read(0, 16)

        # Idempotent close
        reader.close()
        assert not reader.is_open

    def test_nonexistent_file_raises_filenotfound(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist.raw"
        reader = ForensicImageReader(nonexistent)
        with pytest.raises(FileNotFoundError):
            reader.open()
        assert not reader.is_open


class TestEWFAdapterAndMetadata:
    """Verifies EWFImgInfo adapter class and embedded metadata extraction."""

    def test_ewf_adapter_read_and_size(self):
        mock_handle = MagicMock()
        mock_handle.get_media_size.return_value = 1048576
        mock_handle.read.return_value = b"MOCK_EWF_PAYLOAD"

        adapter = EWFImgInfo(mock_handle)
        assert adapter.get_size() == 1048576

        data = adapter.read(100, 16)
        mock_handle.seek_offset.assert_called_once_with(100)
        mock_handle.read.assert_called_once_with(16)
        assert data == b"MOCK_EWF_PAYLOAD"

        adapter.close()

    def test_ewf_metadata_extraction_mocked(self, tmp_path):
        # Create a file with E01 magic header
        e01_path = tmp_path / "case01.E01"
        e01_path.write_bytes(EWF_MAGIC_E01 + b"\x00" * 2048)

        mock_ewf = MagicMock()
        mock_ewf.glob.return_value = [str(e01_path)]

        mock_handle = MagicMock()
        mock_handle.get_media_size.return_value = 5242880
        mock_handle.get_bytes_per_sector.return_value = 512
        mock_handle.get_header_values.return_value = {
            "case_number": "CASE-2026-NIA-007",
            "evidence_number": "EVID-01",
            "examiner_name": "Special Agent DFIR",
            "description": "Suspect primary hard drive",
            "notes": "Acquired via hardware write blocker",
            "acquiry_date": "2026-11-10 10:00:00",
        }
        mock_handle.get_hash_values.return_value = {
            "MD5": "44efa48508e68cf616c8ecba0dca6fa2",
            "SHA1": "3b71f43ff30f4b15b5cd85d60549c3ab71424b40",
            "SHA256": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
        }
        mock_ewf.handle.return_value = mock_handle

        with patch("app.core.image_reader.HAS_PYEWF", True), \
             patch("app.core.image_reader.pyewf", mock_ewf):

            with ForensicImageReader(e01_path) as reader:
                meta = reader.get_metadata()
                assert meta.format_type == "E01"
                assert meta.case_number == "CASE-2026-NIA-007"
                assert meta.evidence_number == "EVID-01"
                assert meta.examiner == "Special Agent DFIR"
                assert meta.notes == "Acquired via hardware write blocker"
                assert meta.stored_md5 == "44efa48508e68cf616c8ecba0dca6fa2"
                assert meta.stored_sha1 == "3b71f43ff30f4b15b5cd85d60549c3ab71424b40"
                assert meta.stored_sha256 == "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d"


class TestDirectVolumeImage:
    """Verifies single unpartitioned volume parsing."""

    def test_direct_volume_without_partition_table(self, tmp_path):
        vol_data = bytearray(100 * 512)
        # Direct NTFS boot sector at sector 0
        vol_data[3:11] = b"NTFS    "
        vol_data[510:512] = b"\x00\x00"  # No MBR signature

        vol_path = tmp_path / "direct_vol.raw"
        vol_path.write_bytes(vol_data)

        with ForensicImageReader(vol_path) as reader:
            parts = reader.enumerate_partitions(force_native=True)
            assert len(parts) == 1
            assert parts[0].slot == 0
            assert parts[0].description == "Direct Volume (No Partition Table)"
            assert parts[0].filesystem_type == "NTFS"
            assert parts[0].start_sector == 0
            assert parts[0].size_bytes == 100 * 512


class TestExtendedPartitionEBR:
    """Verifies MBR Extended Boot Record (EBR) chain walking for logical partitions."""

    def test_mbr_extended_partition_logical_drive(self, tmp_path):
        sector_size = 512
        total_sectors = 300
        disk_data = bytearray(total_sectors * sector_size)

        # Primary Partition 0: NTFS (start=4, count=50)
        p0 = struct.pack("<B3sB3sII", 0x80, b"\x00\x01\x00", 0x07, b"\x00\x02\x00", 4, 50)
        # Primary Partition 1: Extended Partition (0x05) (start=100, count=150)
        p1 = struct.pack("<B3sB3sII", 0x00, b"\x00\x01\x00", 0x05, b"\x00\x02\x00", 100, 150)
        disk_data[446:446 + 16] = p0
        disk_data[462:462 + 16] = p1
        disk_data[510:512] = MBR_BOOT_SIGNATURE

        # At LBA 100 (EBR 1):
        # Entry 1: Logical drive relative to EBR 1 (offset 100). start=1, count=40 -> abs_start=101, FAT32 (0x0B)
        ebr1_part1 = struct.pack("<B3sB3sII", 0x00, b"\x00\x01\x00", 0x0B, b"\x00\x02\x00", 1, 40)
        # Entry 2: Pointer to EBR 2 relative to extended base 100. offset=50 (abs LBA 150)
        ebr1_part2 = struct.pack("<B3sB3sII", 0x00, b"\x00\x01\x00", 0x05, b"\x00\x02\x00", 50, 50)
        disk_data[100 * sector_size + 446:100 * sector_size + 462] = ebr1_part1
        disk_data[100 * sector_size + 462:100 * sector_size + 478] = ebr1_part2
        disk_data[100 * sector_size + 510:100 * sector_size + 512] = MBR_BOOT_SIGNATURE

        # At LBA 150 (EBR 2):
        # Entry 1: Logical drive relative to EBR 2 (offset 150). start=1, count=30 -> abs_start=151, Linux (0x83)
        ebr2_part1 = struct.pack("<B3sB3sII", 0x00, b"\x00\x01\x00", 0x83, b"\x00\x02\x00", 1, 30)
        disk_data[150 * sector_size + 446:150 * sector_size + 462] = ebr2_part1
        disk_data[150 * sector_size + 510:150 * sector_size + 512] = MBR_BOOT_SIGNATURE

        # Plant FAT32 signature at LBA 101
        disk_data[101 * sector_size + 82:101 * sector_size + 90] = b"FAT32   "

        img_path = tmp_path / "extended_mbr.raw"
        img_path.write_bytes(disk_data)

        with ForensicImageReader(img_path) as reader:
            parts = reader.enumerate_partitions(allocated_only=True, force_native=True)
            # Should have: primary p0 (NTFS), and logical drives: LBA 101 (FAT32) and LBA 151 (Linux)
            assert len(parts) == 3
            assert parts[0].start_sector == 4
            assert parts[0].filesystem_type == "NTFS/exFAT"

            assert parts[1].slot == 4
            assert parts[1].start_sector == 101
            assert parts[1].size_bytes == 40 * 512
            assert parts[1].filesystem_type == "FAT32"

            assert parts[2].slot == 5
            assert parts[2].start_sector == 151
            assert parts[2].size_bytes == 30 * 512
            assert parts[2].filesystem_type == "Linux"


class TestPurePythonFallbackWithoutCExtensions:
    """Verifies that the entire tool works seamlessly when pytsk3 and pyewf are unavailable."""

    def test_pure_python_environment(self, tmp_path):
        img_path = create_synthetic_gpt_image(tmp_path)

        with patch("app.core.image_reader.HAS_PYTSK3", False), \
             patch("app.core.image_reader.HAS_PYEWF", False):

            with ForensicImageReader(img_path) as reader:
                assert reader.is_open
                parts = reader.enumerate_partitions(allocated_only=True)
                assert len(parts) == 2
                assert parts[0].description == "Windows_Evidence"
                assert parts[0].filesystem_type == "NTFS"
                assert parts[1].description == "Linux_Root"
                assert parts[1].filesystem_type == "EXT4"

