"""
Strict Read-Only Forensic Image Reader & Partition Enumerator
Department 1: Cyber Triage & Evidence Ingestion (SIH1744 / NIA Specification)
"""

from __future__ import annotations

import os
import struct
import uuid
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# C-Extension Import Handling with Graceful Fallbacks
# ---------------------------------------------------------------------------
try:
    import pyewf
    HAS_PYEWF = True
except ImportError:
    pyewf = None
    HAS_PYEWF = False

try:
    import pytsk3
    HAS_PYTSK3 = True
except ImportError:
    pytsk3 = None
    HAS_PYTSK3 = False


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PartitionInfo:
    """Represents a discovered partition entry or volume segment."""
    slot: int                          # Slot index (e.g., 0, 1, 2 or -1 for unallocated/metadata)
    description: str                   # Human-readable partition description
    filesystem_type: str               # Identified filesystem (e.g., NTFS, FAT32, EXT4, Unknown)
    start_sector: int                  # Logical block addressing (LBA) start sector
    byte_offset: int                   # Byte offset from start of image = start_sector * sector_size
    size_bytes: int                    # Size of partition in bytes
    is_allocated: bool                 # True if allocated partition table entry; False for unallocated
    partition_type_guid: Optional[str] = None  # GPT partition type GUID string if applicable
    partition_type_id: Optional[int] = None    # MBR partition type byte (e.g. 0x07, 0x83) if applicable


@dataclass
class ImageMetadata:
    """Forensic container and acquisition metadata."""
    format_type: str                   # RAW, E01, Ex01, GPT_RAW, MBR_RAW, UNKNOWN
    size_bytes: int                    # Media size in bytes
    sector_size: int = 512             # Sector size (typically 512 or 4096)
    case_number: Optional[str] = None
    evidence_number: Optional[str] = None
    examiner: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    acq_date: Optional[str] = None
    system_date: Optional[str] = None
    stored_md5: Optional[str] = None
    stored_sha1: Optional[str] = None
    stored_sha256: Optional[str] = None
    segment_files: List[str] = field(default_factory=list)
    raw_headers: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Forensic Signatures & Magic Bytes
# ---------------------------------------------------------------------------
EWF_MAGIC_E01 = b"EVF\x09\x0d\x0a\xff\x00"     # EWF v1 (E01)
EWF_MAGIC_L01 = b"LVF\x09\x0d\x0a\xff\x00"     # EWF Logical (L01)
EWF_MAGIC_EX01 = b"EWF2\r\n\x81\x00"           # EWF v2 (Ex01)

MBR_BOOT_SIGNATURE = b"\x55\xaa"               # Offset 510-511
GPT_HEADER_SIGNATURE = b"EFI PART"              # LBA 1 (Offset 512 for 512b sectors)

MBR_PARTITION_TYPES: Dict[int, Tuple[str, str]] = {
    0x01: ("FAT12", "FAT12"),
    0x04: ("FAT16", "FAT16 (<32MB)"),
    0x05: ("Extended", "Extended Partition (CHS)"),
    0x06: ("FAT16", "FAT16 (>32MB)"),
    0x07: ("NTFS/exFAT", "Installable File System (NTFS or exFAT)"),
    0x0B: ("FAT32", "FAT32 (CHS)"),
    0x0C: ("FAT32", "FAT32 (LBA)"),
    0x0E: ("FAT16", "FAT16 (LBA)"),
    0x0F: ("Extended", "Extended Partition (LBA)"),
    0x27: ("Windows RE", "Windows Recovery Environment"),
    0x82: ("Linux Swap", "Linux Swap / Solaris"),
    0x83: ("Linux", "Linux native (ext2/ext3/ext4/xfs)"),
    0x8E: ("Linux LVM", "Linux Logical Volume Manager"),
    0xA5: ("FreeBSD", "FreeBSD Slice"),
    0xAF: ("HFS/HFS+", "macOS HFS / HFS+"),
    0xEE: ("GPT Protective", "EFI GPT Protective MBR"),
    0xEF: ("EFI System", "EFI System Partition"),
}

GPT_PARTITION_TYPES: Dict[str, Tuple[str, str]] = {
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": ("Windows Basic Data", "Basic data partition (NTFS, FAT32, exFAT)"),
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": ("EFI System", "EFI System Partition"),
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": ("Linux Filesystem", "Linux Filesystem Data (ext4, xfs, btrfs)"),
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": ("Microsoft Reserved", "Microsoft Reserved Partition (MSR)"),
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": ("Windows RE", "Windows Recovery Environment"),
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": ("Linux Swap", "Linux Swap Partition"),
    "48465300-0000-11AA-AA11-00306543ECAC": ("HFS+", "Apple HFS+ Partition"),
    "7C345030-0000-11AA-AA11-00306543ECAC": ("APFS", "Apple APFS Container"),
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": ("Linux LVM", "Linux Logical Volume Manager"),
}


# ---------------------------------------------------------------------------
# EWF to pytsk3 Adapter Class
# ---------------------------------------------------------------------------
if HAS_PYTSK3:
    class EWFImgInfo(pytsk3.Img_Info):
        """
        Adapter class subclassing pytsk3.Img_Info wrapping a pyewf handle.
        Enables multi-segment .E01/.E02 forensic containers to mount as a unified
        read-only byte stream for pytsk3 Volume and File System parsers.
        """
        def __init__(self, ewf_handle: Any):
            self._ewf_handle = ewf_handle
            super().__init__()

        def close(self) -> None:
            # Handles are cleaned up safely
            pass

        def read(self, offset: int, size: int) -> bytes:
            self._ewf_handle.seek_offset(offset)
            return self._ewf_handle.read(size)

        def get_size(self) -> int:
            return self._ewf_handle.get_media_size()
else:
    class EWFImgInfo:  # type: ignore
        """Fallback adapter when pytsk3 C-extension is unavailable."""
        def __init__(self, ewf_handle: Any):
            self._ewf_handle = ewf_handle

        def close(self) -> None:
            pass

        def read(self, offset: int, size: int) -> bytes:
            self._ewf_handle.seek_offset(offset)
            return self._ewf_handle.read(size)

        def get_size(self) -> int:
            return self._ewf_handle.get_media_size()


# ---------------------------------------------------------------------------
# Format & Filesystem Inspection Helpers
# ---------------------------------------------------------------------------
def detect_filesystem_signature(read_fn: Callable[[int, int], bytes],
                                start_offset: int,
                                size_bytes: int) -> str:
    """
    Inspects boot sectors and superblocks at a partition offset to determine
    the precise filesystem type independently of partition table declarations.
    """
    try:
        # Read first 1500 bytes of the partition for boot sector & superblock inspection
        sample_len = min(2048, size_bytes)
        if sample_len < 512:
            return "Unknown"
        header = read_fn(start_offset, sample_len)
    except Exception:
        return "Unknown"

    if len(header) < 512:
        return "Unknown"

    # NTFS: OEM-ID at byte 3: "NTFS    "
    if len(header) >= 11 and header[3:11] == b"NTFS    ":
        return "NTFS"

    # exFAT: OEM-ID at byte 3: "EXFAT   "
    if len(header) >= 11 and header[3:11] == b"EXFAT   ":
        return "exFAT"

    # FAT32: FilSysType at offset 82 (0x52): "FAT32   "
    if len(header) >= 90 and header[82:90] == b"FAT32   ":
        return "FAT32"

    # FAT12 / FAT16: FilSysType at offset 54 (0x36): "FAT12   " or "FAT16   "
    if len(header) >= 62:
        if header[54:62] == b"FAT16   ":
            return "FAT16"
        if header[54:62] == b"FAT12   ":
            return "FAT12"

    # EXT2 / EXT3 / EXT4: Superblock at offset 1024; magic 0xEF53 at offset 1024 + 56 = 1080
    if len(header) >= 1082:
        if header[1080:1082] == b"\x53\xef":
            return "EXT4"

    # APFS: Container superblock magic "NXSB" at offset 0
    if len(header) >= 4 and header[0:4] == b"NXSB":
        return "APFS"

    # HFS+: Volume header signature "H+" or "HX" at offset 1024
    if len(header) >= 1026 and header[1024:1026] in (b"H+", b"HX"):
        return "HFS+"

    # XFS: Superblock magic "XFSB" at offset 0
    if len(header) >= 4 and header[0:4] == b"XFSB":
        return "XFS"

    # Check for general FAT boot sector jump code (0xEB 0x?? 0x90) with 0x55AA signature
    if header[0] in (0xEB, 0xE9) and header[510:512] == b"\x55\xaa":
        return "FAT"

    return "Unknown"


def detect_image_format(header_sample: bytes) -> str:
    """
    Inspects magic bytes in the initial sample (at least 1024 bytes) to classify
    the disk image or forensic container format.
    """
    if len(header_sample) >= 8:
        if header_sample[:8] in (EWF_MAGIC_E01, EWF_MAGIC_L01):
            return "E01"
        if header_sample[:8] == EWF_MAGIC_EX01:
            return "Ex01"

    # Check GPT at LBA 1 (offset 512)
    if len(header_sample) >= 520 and header_sample[512:520] == GPT_HEADER_SIGNATURE:
        return "GPT_RAW"

    # Check MBR boot signature at offset 510
    if len(header_sample) >= 512 and header_sample[510:512] == MBR_BOOT_SIGNATURE:
        return "MBR_RAW"

    return "RAW"


# ---------------------------------------------------------------------------
# ForensicImageReader
# ---------------------------------------------------------------------------
class ForensicImageReader:
    """
    High-assurance, strict read-only forensic image abstraction.
    Supports RAW disk images (.dd, .raw, .img) and Expert Witness Format (.E01, .Ex01).
    Provides unified read access, metadata inspection, and partition table enumeration
    with automatic fallbacks when C-extensions (pyewf/pytsk3) are unavailable.
    """
    def __init__(self, path: Union[str, Path], sector_size: int = 512):
        self._path = Path(path).resolve()
        self._sector_size = sector_size
        self._is_open = False

        # Raw file handle
        self._raw_file = None
        self._raw_size = 0

        # EWF handle and segments
        self._ewf_handle = None
        self._segment_files: List[str] = []

        # TSK abstraction
        self._tsk_img_info: Any = None

        # Container metadata
        self._format_type = "UNKNOWN"
        self._metadata: Optional[ImageMetadata] = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def is_open(self) -> bool:
        return self._is_open

    @property
    def sector_size(self) -> int:
        return self._sector_size

    def __enter__(self) -> ForensicImageReader:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def open(self) -> None:
        """
        Opens the forensic image in strict read-only mode and inspects format and metadata.
        Guarantees safe cleanup on failure.
        """
        if self._is_open:
            return

        if not self._path.exists():
            raise FileNotFoundError(f"Forensic image file not found: {self._path}")

        try:
            # Read header probe from disk
            with open(self._path, "rb") as probe_f:
                probe_sample = probe_f.read(4096)

            self._format_type = detect_image_format(probe_sample)

            if self._format_type in ("E01", "Ex01") and HAS_PYEWF:
                self._open_ewf()
            else:
                self._open_raw()

            self._is_open = True
            self._load_metadata()

        except Exception:
            self.close()
            raise

    def _open_ewf(self) -> None:
        """Mounts multi-segment EWF container via pyewf."""
        try:
            # Discover segment files (.E01, .E02, etc.)
            self._segment_files = pyewf.glob(str(self._path))
        except Exception:
            self._segment_files = [str(self._path)]

        if not self._segment_files:
            self._segment_files = [str(self._path)]

        self._ewf_handle = pyewf.handle()
        self._ewf_handle.open(self._segment_files)
        self._raw_size = self._ewf_handle.get_media_size()
        bytes_per_sec = self._ewf_handle.get_bytes_per_sector()
        if bytes_per_sec and bytes_per_sec > 0:
            self._sector_size = bytes_per_sec

        if HAS_PYTSK3:
            self._tsk_img_info = EWFImgInfo(self._ewf_handle)

    def _open_raw(self) -> None:
        """Opens raw image (.raw, .dd, .img) in strictly read-only binary mode."""
        self._raw_file = open(self._path, "rb")
        self._raw_file.seek(0, os.SEEK_END)
        self._raw_size = self._raw_file.tell()
        self._raw_file.seek(0)
        self._segment_files = [str(self._path)]

        if HAS_PYTSK3:
            try:
                self._tsk_img_info = pytsk3.Img_Info(str(self._path))
            except Exception:
                self._tsk_img_info = None

    def _load_metadata(self) -> None:
        """Extracts container metadata and stored acquisition hashes."""
        case_no = None
        ev_no = None
        examiner = None
        desc = None
        notes = None
        acq_date = None
        sys_date = None
        stored_md5 = None
        stored_sha1 = None
        stored_sha256 = None
        raw_headers: Dict[str, Any] = {}

        if self._ewf_handle is not None and HAS_PYEWF:
            try:
                headers = self._ewf_handle.get_header_values()
                raw_headers = dict(headers) if headers else {}
                case_no = raw_headers.get("case_number")
                ev_no = raw_headers.get("evidence_number")
                examiner = raw_headers.get("examiner_name")
                desc = raw_headers.get("description")
                notes = raw_headers.get("notes")
                acq_date = raw_headers.get("acquiry_date")
                sys_date = raw_headers.get("system_date")
            except Exception:
                pass

            try:
                hashes = self._ewf_handle.get_hash_values()
                if hashes:
                    for k, v in hashes.items():
                        k_upper = str(k).upper()
                        if "MD5" in k_upper:
                            stored_md5 = str(v)
                        elif "SHA1" in k_upper or "SHA-1" in k_upper:
                            stored_sha1 = str(v)
                        elif "SHA256" in k_upper or "SHA-256" in k_upper:
                            stored_sha256 = str(v)
            except Exception:
                pass

            # Fallback direct lookup for hashes
            try:
                if not stored_md5:
                    stored_md5 = self._ewf_handle.get_hash_value("MD5")
                if not stored_sha1:
                    stored_sha1 = self._ewf_handle.get_hash_value("SHA1")
                if not stored_sha256:
                    stored_sha256 = self._ewf_handle.get_hash_value("SHA256")
            except Exception:
                pass

        self._metadata = ImageMetadata(
            format_type=self._format_type,
            size_bytes=self._raw_size,
            sector_size=self._sector_size,
            case_number=case_no,
            evidence_number=ev_no,
            examiner=examiner,
            description=desc,
            notes=notes,
            acq_date=acq_date,
            system_date=sys_date,
            stored_md5=stored_md5,
            stored_sha1=stored_sha1,
            stored_sha256=stored_sha256,
            segment_files=list(self._segment_files),
            raw_headers=raw_headers,
        )

    def get_metadata(self) -> ImageMetadata:
        """Returns the parsed container metadata and acquisition hashes."""
        if not self._is_open or self._metadata is None:
            raise ValueError("Forensic image is not open.")
        return self._metadata

    def read(self, offset: int, size: int) -> bytes:
        """
        Unified, strict read-only byte slice retrieval across RAW and EWF containers.
        Raises ValueError on negative offsets or closed handles.
        """
        if not self._is_open:
            raise ValueError("I/O operation on closed ForensicImageReader.")
        if offset < 0 or size < 0:
            raise ValueError(f"Invalid read parameters: offset={offset}, size={size}")
        if size == 0:
            return b""
        if offset >= self._raw_size:
            return b""

        clamped_size = min(size, self._raw_size - offset)

        if self._ewf_handle is not None:
            self._ewf_handle.seek_offset(offset)
            return self._ewf_handle.read(clamped_size)

        if self._raw_file is not None:
            self._raw_file.seek(offset)
            return self._raw_file.read(clamped_size)

        raise IOError("No valid underlying file handle available for read.")

    def write(self, *args, **kwargs) -> None:
        """Strictly disallows write operations on forensic evidence."""
        raise PermissionError("Forensic evidence is strictly read-only. Write operations are forbidden.")

    def close(self) -> None:
        """Idempotent teardown releasing all C-extension and OS file descriptors cleanly."""
        if self._tsk_img_info is not None:
            try:
                self._tsk_img_info.close()
            except Exception:
                pass
            self._tsk_img_info = None

        if self._ewf_handle is not None:
            try:
                self._ewf_handle.close()
            except Exception:
                pass
            self._ewf_handle = None

        if self._raw_file is not None:
            try:
                self._raw_file.close()
            except Exception:
                pass
            self._raw_file = None

        self._is_open = False

    # -----------------------------------------------------------------------
    # Partition Enumeration
    # -----------------------------------------------------------------------
    def enumerate_partitions(self,
                             allocated_only: bool = False,
                             force_native: bool = False) -> List[PartitionInfo]:
        """
        Enumerates all partitions across the disk image.
        Prioritizes pytsk3 Volume System parsing if available; falls back automatically
        to the pure-Python native MBR/GPT parser on missing extensions or corrupted volume headers.
        """
        if not self._is_open:
            raise ValueError("Forensic image is not open.")

        if HAS_PYTSK3 and not force_native and self._tsk_img_info is not None:
            try:
                return self._enumerate_partitions_tsk(allocated_only=allocated_only)
            except Exception:
                # On any TSK volume system error, cleanly fall back to native Python parsing
                pass

        return self._enumerate_partitions_native(allocated_only=allocated_only)

    def _enumerate_partitions_tsk(self, allocated_only: bool = False) -> List[PartitionInfo]:
        """Parses partitions using pytsk3.Volume_Info."""
        vs = pytsk3.Volume_Info(self._tsk_img_info)
        partitions: List[PartitionInfo] = []
        block_size = vs.info.block_size or self._sector_size

        for part in vs:
            is_alloc = bool(part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC)
            if allocated_only and not is_alloc:
                continue

            desc_str = part.desc.decode("utf-8", errors="replace") if isinstance(part.desc, bytes) else str(part.desc)
            start_sec = part.start
            byte_off = start_sec * block_size
            size_b = part.len * block_size

            # Probe filesystem if partition is allocated
            fs_type = "Unknown"
            if is_alloc:
                fs_type = detect_filesystem_signature(self.read, byte_off, size_b)
                if fs_type == "Unknown":
                    # Attempt pytsk3 FS_Info probe
                    try:
                        fs_info = pytsk3.FS_Info(self._tsk_img_info, offset=byte_off)
                        fs_type = str(fs_info.info.ftype).replace("TSK_FS_TYPE_", "")
                    except Exception:
                        fs_type = desc_str

            partitions.append(PartitionInfo(
                slot=part.slot_num,
                description=desc_str,
                filesystem_type=fs_type,
                start_sector=start_sec,
                byte_offset=byte_off,
                size_bytes=size_b,
                is_allocated=is_alloc,
            ))

        return partitions

    def _enumerate_partitions_native(self, allocated_only: bool = False) -> List[PartitionInfo]:
        """
        Pure-Python native parser for MBR and GPT partition tables.
        Provides resilient partition analysis with zero external C-dependencies.
        """
        sample = self.read(0, 2048)
        if len(sample) < 512:
            return []

        # 1. Test for GPT Header at LBA 1 (Offset 512)
        if len(sample) >= 520 and sample[512:520] == GPT_HEADER_SIGNATURE:
            return self._parse_gpt_native(allocated_only=allocated_only)

        # 2. Test for MBR Boot Signature at Offset 510
        if sample[510:512] == MBR_BOOT_SIGNATURE:
            # Check if this is a protective MBR pointing to GPT beyond first 2048 bytes
            first_type = sample[446 + 4]
            if first_type == 0xEE:
                # Protective MBR: Attempt to parse GPT
                gpt_parts = self._parse_gpt_native(allocated_only=allocated_only)
                if gpt_parts:
                    return gpt_parts
            return self._parse_mbr_native(sample, allocated_only=allocated_only)

        # 3. Direct Filesystem (Superfloppy / Raw Volume)
        fs_type = detect_filesystem_signature(self.read, 0, self._raw_size)
        if fs_type != "Unknown":
            return [PartitionInfo(
                slot=0,
                description="Direct Volume (No Partition Table)",
                filesystem_type=fs_type,
                start_sector=0,
                byte_offset=0,
                size_bytes=self._raw_size,
                is_allocated=True,
            )]

        return []

    def _parse_gpt_native(self, allocated_only: bool = False) -> List[PartitionInfo]:
        """Parses GUID Partition Table (GPT) natively using struct and uuid."""
        header_data = self.read(self._sector_size, 92)
        if len(header_data) < 92 or header_data[:8] != GPT_HEADER_SIGNATURE:
            return []

        try:
            (signature,
             revision,
             header_size,
             header_crc,
             reserved,
             current_lba,
             backup_lba,
             first_usable_lba,
             last_usable_lba,
             disk_guid_raw,
             partition_entries_lba,
             num_partition_entries,
             entry_size,
             partition_entries_crc) = struct.unpack("<8sIIIIQQQQ16sQIII", header_data[:92])
        except Exception:
            return []

        # Sanity check parameters
        if num_partition_entries == 0 or entry_size < 128:
            return []

        entries_size = num_partition_entries * entry_size
        entries_data = self.read(partition_entries_lba * self._sector_size, entries_size)

        partitions: List[PartitionInfo] = []
        zero_guid = b"\x00" * 16

        for slot_idx in range(num_partition_entries):
            offset = slot_idx * entry_size
            if offset + entry_size > len(entries_data):
                break

            entry = entries_data[offset:offset + entry_size]
            type_guid_raw = entry[:16]

            # Unused entry
            if type_guid_raw == zero_guid:
                continue

            type_guid_str = str(uuid.UUID(bytes_le=type_guid_raw)).upper()
            start_lba, end_lba, attrs = struct.unpack("<QQQ", entry[32:56])
            name_raw = entry[56:128]
            partition_name = name_raw.decode("utf-16le", errors="replace").rstrip("\x00").strip()

            type_info = GPT_PARTITION_TYPES.get(type_guid_str)
            friendly_name = type_info[0] if type_info else "Basic Data"
            desc = partition_name if partition_name else friendly_name

            sector_count = (end_lba - start_lba + 1) if end_lba >= start_lba else 0
            byte_offset = start_lba * self._sector_size
            size_bytes = sector_count * self._sector_size

            # Probe actual filesystem inside partition
            fs_type = detect_filesystem_signature(self.read, byte_offset, size_bytes)
            if fs_type == "Unknown":
                fs_type = friendly_name

            partitions.append(PartitionInfo(
                slot=slot_idx,
                description=desc,
                filesystem_type=fs_type,
                start_sector=start_lba,
                byte_offset=byte_offset,
                size_bytes=size_bytes,
                is_allocated=True,
                partition_type_guid=type_guid_str,
            ))

        if not allocated_only:
            partitions = self._insert_unallocated_gaps(partitions)

        return partitions

    def _parse_mbr_native(self, sector0: bytes, allocated_only: bool = False) -> List[PartitionInfo]:
        """Parses Master Boot Record (MBR) and walks extended partition chains."""
        partitions: List[PartitionInfo] = []
        extended_partitions: List[Tuple[int, int]] = []

        # Read 4 primary partition records from offset 446 (0x1BE)
        for slot_idx in range(4):
            entry_offset = 446 + slot_idx * 16
            entry = sector0[entry_offset:entry_offset + 16]
            bootable, start_chs, part_type, end_chs, start_lba, num_sectors = struct.unpack(
                "<B3sB3sII", entry
            )

            if part_type == 0x00 or num_sectors == 0:
                continue

            type_info = MBR_PARTITION_TYPES.get(part_type, (f"Type 0x{part_type:02X}", f"Unknown (0x{part_type:02X})"))
            type_name = type_info[0]
            byte_offset = start_lba * self._sector_size
            size_bytes = num_sectors * self._sector_size

            # Check if this is an extended partition container (0x05 or 0x0F)
            if part_type in (0x05, 0x0F):
                extended_partitions.append((start_lba, num_sectors))
                if not allocated_only:
                    partitions.append(PartitionInfo(
                        slot=slot_idx,
                        description=type_info[1],
                        filesystem_type=type_name,
                        start_sector=start_lba,
                        byte_offset=byte_offset,
                        size_bytes=size_bytes,
                        is_allocated=True,
                        partition_type_id=part_type,
                    ))
                continue

            fs_type = detect_filesystem_signature(self.read, byte_offset, size_bytes)
            if fs_type == "Unknown":
                fs_type = type_name

            partitions.append(PartitionInfo(
                slot=slot_idx,
                description=type_info[1],
                filesystem_type=fs_type,
                start_sector=start_lba,
                byte_offset=byte_offset,
                size_bytes=size_bytes,
                is_allocated=True,
                partition_type_id=part_type,
            ))

        # Walk Extended Boot Record (EBR) chains for logical partitions
        logical_slot = 4
        for ext_start_lba, ext_num_sectors in extended_partitions:
            current_ebr_lba = ext_start_lba
            visited_ebrs = set()

            while current_ebr_lba and current_ebr_lba not in visited_ebrs:
                visited_ebrs.add(current_ebr_lba)
                ebr_bytes = self.read(current_ebr_lba * self._sector_size, 512)
                if len(ebr_bytes) < 512 or ebr_bytes[510:512] != MBR_BOOT_SIGNATURE:
                    break

                # First entry: Logical partition relative to current EBR
                ebr1 = ebr_bytes[446:462]
                _, _, p_type1, _, rel_start1, sec_count1 = struct.unpack("<B3sB3sII", ebr1)

                if p_type1 != 0x00 and sec_count1 > 0:
                    abs_start = current_ebr_lba + rel_start1
                    byte_off = abs_start * self._sector_size
                    sz_bytes = sec_count1 * self._sector_size
                    t_info = MBR_PARTITION_TYPES.get(p_type1, (f"Type 0x{p_type1:02X}", f"Unknown (0x{p_type1:02X})"))
                    fs_probe = detect_filesystem_signature(self.read, byte_off, sz_bytes)
                    if fs_probe == "Unknown":
                        fs_probe = t_info[0]

                    partitions.append(PartitionInfo(
                        slot=logical_slot,
                        description=f"Logical: {t_info[1]}",
                        filesystem_type=fs_probe,
                        start_sector=abs_start,
                        byte_offset=byte_off,
                        size_bytes=sz_bytes,
                        is_allocated=True,
                        partition_type_id=p_type1,
                    ))
                    logical_slot += 1

                # Second entry: Pointer to next EBR relative to base extended partition
                ebr2 = ebr_bytes[462:478]
                _, _, p_type2, _, next_rel_lba, _ = struct.unpack("<B3sB3sII", ebr2)
                if p_type2 != 0x00 and next_rel_lba > 0:
                    current_ebr_lba = ext_start_lba + next_rel_lba
                else:
                    break

        if not allocated_only:
            partitions = self._insert_unallocated_gaps(partitions)

        return partitions

    def _insert_unallocated_gaps(self, partitions: List[PartitionInfo]) -> List[PartitionInfo]:
        """Computes unallocated sector ranges and interleaves them with allocated partitions."""
        if not partitions:
            if self._raw_size > 0:
                total_sectors = self._raw_size // self._sector_size
                return [PartitionInfo(
                    slot=-1,
                    description="Unallocated",
                    filesystem_type="Unallocated",
                    start_sector=0,
                    byte_offset=0,
                    size_bytes=self._raw_size,
                    is_allocated=False,
                )]
            return []

        sorted_parts = sorted(partitions, key=lambda p: p.start_sector)
        result: List[PartitionInfo] = []
        current_sector = 0

        for p in sorted_parts:
            if p.start_sector > current_sector:
                gap_sectors = p.start_sector - current_sector
                gap_bytes = gap_sectors * self._sector_size
                result.append(PartitionInfo(
                    slot=-1,
                    description="Unallocated",
                    filesystem_type="Unallocated",
                    start_sector=current_sector,
                    byte_offset=current_sector * self._sector_size,
                    size_bytes=gap_bytes,
                    is_allocated=False,
                ))
            result.append(p)
            current_sector = max(current_sector, p.start_sector + (p.size_bytes // self._sector_size))

        total_disk_sectors = self._raw_size // self._sector_size
        if current_sector < total_disk_sectors:
            tail_sectors = total_disk_sectors - current_sector
            tail_bytes = tail_sectors * self._sector_size
            result.append(PartitionInfo(
                slot=-1,
                description="Unallocated",
                filesystem_type="Unallocated",
                start_sector=current_sector,
                byte_offset=current_sector * self._sector_size,
                size_bytes=tail_bytes,
                is_allocated=False,
            ))

        return result

