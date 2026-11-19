"""
Streaming Hasher & Verification Engine (Evidence Intake Worker)
Department 1: Cyber Triage & Evidence Ingestion (SIH1744 / NIA Specification)
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from .image_reader import ForensicImageReader, PartitionInfo

# Default chunk size: 8 megabytes for high-throughput streaming
DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024


# ---------------------------------------------------------------------------
# Data Models & Exceptions
# ---------------------------------------------------------------------------
class OperationCancelledError(Exception):
    """Raised when evidence verification or hashing is cancelled by the investigator."""
    pass


@dataclass(frozen=True)
class HashProgress:
    """Snapshot of active evidence streaming and hashing throughput."""
    bytes_processed: int
    total_bytes: int
    progress_percent: float
    throughput_mb_s: float
    elapsed_sec: float
    estimated_remaining_sec: Optional[float] = None


@dataclass
class IntakeVerificationResult:
    """Forensic verification report comparing computed hashes against acquisition records."""
    image_path: Path
    format_type: str
    total_bytes: int
    hashes: Dict[str, str]                       # {"md5": ..., "sha1": ..., "sha256": ...}
    embedded_hashes: Dict[str, str]              # Acquisition hashes extracted from container headers
    is_verified: bool                            # True if no mismatch detected against embedded records
    mismatch_details: List[str]                  # Detailed breakdown of any hash discrepancies
    partitions: List[PartitionInfo]              # Discovered partition table entries
    duration_sec: float                          # Total execution time in seconds
    throughput_mb_s: float                       # Average hashing throughput across the stream
    cancelled: bool = False                      # True if worker was cancelled before completion
    error: Optional[str] = None                  # Error message if an unhandled failure occurred


# ---------------------------------------------------------------------------
# Decoupled Streaming Hasher Service
# ---------------------------------------------------------------------------
class EvidenceHasher:
    """
    Decoupled streaming hashing and integrity verification service for forensic evidence.
    Streams uncompressed evidence blocks in 8MB chunks via ForensicImageReader
    to compute SHA-256, SHA-1, and MD5 in a single unified pass.
    """
    def __init__(self,
                 chunk_size: int = DEFAULT_CHUNK_SIZE,
                 cancel_event: Optional[threading.Event] = None):
        self.chunk_size = max(512, chunk_size)
        self._cancel_event = cancel_event or threading.Event()

    @property
    def cancel_event(self) -> threading.Event:
        return self._cancel_event

    def cancel(self) -> None:
        """Signals thread-safe cancellation."""
        self._cancel_event.set()

    def is_cancelled(self) -> bool:
        """Returns True if cancellation has been requested."""
        return self._cancel_event.is_set()

    def verify_image(self,
                     image_path: Union[str, Path],
                     progress_callback: Optional[Callable[[HashProgress], None]] = None,
                     expected_hashes: Optional[Dict[str, str]] = None,
                     enumerate_partitions: bool = True) -> IntakeVerificationResult:
        """
        Streams through the evidence container, calculates MD5, SHA-1, and SHA-256 digests
        in a single pass, validates against embedded or expected hashes, and returns
        a structured forensic verification record.
        """
        image_path = Path(image_path).resolve()
        start_time = time.perf_counter()

        with ForensicImageReader(image_path) as reader:
            metadata = reader.get_metadata()
            total_bytes = metadata.size_bytes
            format_type = metadata.format_type

            # Initialise cryptographic hash contexts
            md5_ctx = hashlib.md5()
            sha1_ctx = hashlib.sha1()
            sha256_ctx = hashlib.sha256()

            bytes_processed = 0
            offset = 0

            # Single-pass streaming read loop
            while offset < total_bytes:
                if self.is_cancelled():
                    duration = max(time.perf_counter() - start_time, 0.0001)
                    return IntakeVerificationResult(
                        image_path=image_path,
                        format_type=format_type,
                        total_bytes=total_bytes,
                        hashes={},
                        embedded_hashes={},
                        is_verified=False,
                        mismatch_details=["Evidence hashing was cancelled by investigator."],
                        partitions=[],
                        duration_sec=duration,
                        throughput_mb_s=(bytes_processed / (1024 * 1024)) / duration,
                        cancelled=True,
                        error="Operation cancelled by user",
                    )

                read_size = min(self.chunk_size, total_bytes - offset)
                chunk = reader.read(offset, read_size)
                if not chunk:
                    break

                md5_ctx.update(chunk)
                sha1_ctx.update(chunk)
                sha256_ctx.update(chunk)

                bytes_processed += len(chunk)
                offset += len(chunk)

                if progress_callback:
                    elapsed = max(time.perf_counter() - start_time, 0.0001)
                    mb_proc = bytes_processed / (1024 * 1024)
                    throughput = mb_proc / elapsed
                    pct = (bytes_processed / total_bytes * 100.0) if total_bytes > 0 else 100.0
                    rem_bytes = max(0, total_bytes - bytes_processed)
                    eta = (rem_bytes / (1024 * 1024)) / throughput if throughput > 0 else 0.0

                    progress_callback(HashProgress(
                        bytes_processed=bytes_processed,
                        total_bytes=total_bytes,
                        progress_percent=pct,
                        throughput_mb_s=throughput,
                        elapsed_sec=elapsed,
                        estimated_remaining_sec=eta,
                    ))

            # Finalize computed cryptographic digests
            computed_hashes = {
                "md5": md5_ctx.hexdigest().lower(),
                "sha1": sha1_ctx.hexdigest().lower(),
                "sha256": sha256_ctx.hexdigest().lower(),
            }

            # Extract embedded container acquisition hashes
            embedded_hashes: Dict[str, str] = {}
            if metadata.stored_md5:
                embedded_hashes["md5"] = metadata.stored_md5.lower().strip()
            if metadata.stored_sha1:
                embedded_hashes["sha1"] = metadata.stored_sha1.lower().strip()
            if metadata.stored_sha256:
                embedded_hashes["sha256"] = metadata.stored_sha256.lower().strip()

            # Target hashes combining embedded metadata and explicit investigator input
            target_hashes = dict(embedded_hashes)
            if expected_hashes:
                for k, v in expected_hashes.items():
                    if v:
                        target_hashes[k.lower()] = v.lower().strip()

            # Compare computed digests against target records
            mismatch_details: List[str] = []
            is_verified = True

            if target_hashes:
                for algo, target_val in target_hashes.items():
                    if algo in computed_hashes:
                        actual_val = computed_hashes[algo]
                        if actual_val != target_val:
                            is_verified = False
                            mismatch_details.append(
                                f"{algo.upper()} mismatch: expected '{target_val}', computed '{actual_val}'"
                            )

            # Enumerate partitions if requested
            partitions: List[PartitionInfo] = []
            if enumerate_partitions:
                try:
                    partitions = reader.enumerate_partitions()
                except Exception as exc:
                    mismatch_details.append(f"Partition discovery notice: {exc}")

            duration = max(time.perf_counter() - start_time, 0.0001)
            avg_throughput = (bytes_processed / (1024 * 1024)) / duration

            # Final 100% progress notification if callback registered
            if progress_callback:
                progress_callback(HashProgress(
                    bytes_processed=bytes_processed,
                    total_bytes=total_bytes,
                    progress_percent=100.0,
                    throughput_mb_s=avg_throughput,
                    elapsed_sec=duration,
                    estimated_remaining_sec=0.0,
                ))

            return IntakeVerificationResult(
                image_path=image_path,
                format_type=format_type,
                total_bytes=total_bytes,
                hashes=computed_hashes,
                embedded_hashes=embedded_hashes,
                is_verified=is_verified,
                mismatch_details=mismatch_details,
                partitions=partitions,
                duration_sec=duration,
                throughput_mb_s=avg_throughput,
                cancelled=False,
                error=None,
            )


# ---------------------------------------------------------------------------
# Fallback Emitter & Worker (Zero-dependency headless CLI mode)
# ---------------------------------------------------------------------------
class FallbackWorkerSignals:
    """Headless signal-compatible emitter for environments where PySide6 is unavailable."""
    def __init__(self):
        self._slots: Dict[str, List[Callable]] = {
            "progress": [],
            "finished": [],
            "error": [],
            "cancelled": [],
        }

    class _SignalEmitter:
        def __init__(self, callbacks: List[Callable]):
            self._callbacks = callbacks

        def connect(self, slot: Callable) -> None:
            self._callbacks.append(slot)

        def emit(self, *args, **kwargs) -> None:
            for cb in list(self._callbacks):
                try:
                    cb(*args, **kwargs)
                except Exception:
                    pass

    @property
    def progress(self) -> FallbackWorkerSignals._SignalEmitter:
        return self._SignalEmitter(self._slots["progress"])

    @property
    def finished(self) -> FallbackWorkerSignals._SignalEmitter:
        return self._SignalEmitter(self._slots["finished"])

    @property
    def error(self) -> FallbackWorkerSignals._SignalEmitter:
        return self._SignalEmitter(self._slots["error"])

    @property
    def cancelled(self) -> FallbackWorkerSignals._SignalEmitter:
        return self._SignalEmitter(self._slots["cancelled"])


class FallbackIntakeWorker:
    """Headless fallback worker when PySide6 is not imported."""
    def __init__(self,
                 image_path: Union[str, Path],
                 chunk_size: int = DEFAULT_CHUNK_SIZE,
                 expected_hashes: Optional[Dict[str, str]] = None,
                 enumerate_partitions: bool = True):
        self.image_path = Path(image_path)
        self.chunk_size = chunk_size
        self.expected_hashes = expected_hashes
        self.enumerate_partitions = enumerate_partitions
        self.signals = FallbackWorkerSignals()
        self._hasher = EvidenceHasher(chunk_size=chunk_size)

    def cancel(self) -> None:
        self._hasher.cancel()

    def run(self) -> None:
        try:
            def on_progress(p: HashProgress) -> None:
                self.signals.progress.emit(
                    p.progress_percent,
                    p.throughput_mb_s,
                    p.bytes_processed,
                    p.total_bytes
                )

            result = self._hasher.verify_image(
                image_path=self.image_path,
                progress_callback=on_progress,
                expected_hashes=self.expected_hashes,
                enumerate_partitions=self.enumerate_partitions,
            )

            if result.cancelled:
                self.signals.cancelled.emit()
            else:
                self.signals.finished.emit(result)

        except OperationCancelledError:
            self.signals.cancelled.emit()
        except Exception as exc:
            self.signals.error.emit(str(exc))


# ---------------------------------------------------------------------------
# PySide6 QRunnable Worker
# ---------------------------------------------------------------------------
try:
    from PySide6.QtCore import QObject, QRunnable, Signal, Slot
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False


if HAS_PYSIDE6:
    class IntakeWorkerSignals(QObject):
        """Qt signal interface for evidence intake progress and completion."""
        # progress_pct, throughput_mb_s, bytes_processed, total_bytes
        progress = Signal(float, float, int, int)
        finished = Signal(object)      # IntakeVerificationResult
        error = Signal(str)            # Error message
        cancelled = Signal()           # Cancellation acknowledgment

    class QtEvidenceIntakeWorker(QRunnable):
        """
        PySide6 QRunnable worker for background evidence verification.
        Emits progress and completion signals onto the Qt event loop.
        """
        def __init__(self,
                     image_path: Union[str, Path],
                     chunk_size: int = DEFAULT_CHUNK_SIZE,
                     expected_hashes: Optional[Dict[str, str]] = None,
                     enumerate_partitions: bool = True):
            super().__init__()
            self.image_path = Path(image_path)
            self.chunk_size = chunk_size
            self.expected_hashes = expected_hashes
            self.enumerate_partitions = enumerate_partitions
            self.signals = IntakeWorkerSignals()
            self._hasher = EvidenceHasher(chunk_size=chunk_size)

        def cancel(self) -> None:
            """Signals cancellation of the underlying streaming hasher."""
            self._hasher.cancel()

        @Slot()
        def run(self) -> None:
            """Entrypoint executed inside a QThreadPool thread."""
            try:
                def on_progress(p: HashProgress) -> None:
                    self.signals.progress.emit(
                        p.progress_percent,
                        p.throughput_mb_s,
                        p.bytes_processed,
                        p.total_bytes
                    )

                result = self._hasher.verify_image(
                    image_path=self.image_path,
                    progress_callback=on_progress,
                    expected_hashes=self.expected_hashes,
                    enumerate_partitions=self.enumerate_partitions,
                )

                if result.cancelled:
                    self.signals.cancelled.emit()
                else:
                    self.signals.finished.emit(result)

            except OperationCancelledError:
                self.signals.cancelled.emit()
            except Exception as exc:
                self.signals.error.emit(str(exc))

    EvidenceIntakeWorker = QtEvidenceIntakeWorker
else:
    EvidenceIntakeWorker = FallbackIntakeWorker
