"""
Unit Tests for Streaming Hasher & Verification Engine (Evidence Intake Worker)
Department 1: Cyber Triage & Evidence Ingestion (SIH1744 / NIA Specification)
"""

import hashlib
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.core.image_reader import ForensicImageReader
from app.core.intake_worker import (
    DEFAULT_CHUNK_SIZE,
    EvidenceHasher,
    EvidenceIntakeWorker,
    HashProgress,
    IntakeVerificationResult,
    OperationCancelledError,
)
from tests.test_image_reader import create_synthetic_gpt_image, create_synthetic_mbr_image


# ---------------------------------------------------------------------------
# Test Cases for EvidenceHasher Service
# ---------------------------------------------------------------------------
class TestEvidenceHasher:
    """Verifies single-pass cryptographic hashing, chunk streaming, and verification."""

    def test_single_pass_hashes_match_hashlib(self, tmp_path):
        # Create a synthetic MBR image
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=300)
        raw_bytes = img_path.read_bytes()

        # Compute ground truth hashes
        expected_md5 = hashlib.md5(raw_bytes).hexdigest().lower()
        expected_sha1 = hashlib.sha1(raw_bytes).hexdigest().lower()
        expected_sha256 = hashlib.sha256(raw_bytes).hexdigest().lower()

        # Use small chunk size to enforce multi-chunk streaming
        hasher = EvidenceHasher(chunk_size=16 * 1024)
        progress_events = []

        def on_progress(p: HashProgress):
            progress_events.append(p)

        result = hasher.verify_image(img_path, progress_callback=on_progress)

        assert isinstance(result, IntakeVerificationResult)
        assert result.total_bytes == len(raw_bytes)
        assert result.hashes["md5"] == expected_md5
        assert result.hashes["sha1"] == expected_sha1
        assert result.hashes["sha256"] == expected_sha256
        assert result.is_verified is True
        assert len(result.mismatch_details) == 0
        assert result.cancelled is False
        assert result.duration_sec > 0
        assert result.throughput_mb_s > 0

        # Verify progress events were emitted
        assert len(progress_events) > 0
        assert progress_events[-1].progress_percent == 100.0
        assert progress_events[-1].bytes_processed == len(raw_bytes)

    def test_expected_hashes_validation_match(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=100)
        raw_bytes = img_path.read_bytes()
        expected_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        hasher = EvidenceHasher()
        result = hasher.verify_image(
            img_path,
            expected_hashes={"sha256": expected_sha256}
        )

        assert result.is_verified is True
        assert len(result.mismatch_details) == 0

    def test_expected_hashes_validation_mismatch(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=100)
        hasher = EvidenceHasher()
        result = hasher.verify_image(
            img_path,
            expected_hashes={"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}
        )

        assert result.is_verified is False
        assert len(result.mismatch_details) == 1
        assert "SHA256 mismatch" in result.mismatch_details[0]

    def test_embedded_hashes_verification_from_metadata(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=50)
        raw_bytes = img_path.read_bytes()
        actual_md5 = hashlib.md5(raw_bytes).hexdigest()
        actual_sha1 = hashlib.sha1(raw_bytes).hexdigest()

        # Mock metadata returning embedded acquisition hashes
        with patch.object(ForensicImageReader, "get_metadata") as mock_meta:
            mock_meta.return_value = MagicMock(
                format_type="E01",
                size_bytes=len(raw_bytes),
                stored_md5=actual_md5,
                stored_sha1=actual_sha1,
                stored_sha256=None,
            )

            hasher = EvidenceHasher()
            result = hasher.verify_image(img_path)

            assert result.is_verified is True
            assert result.embedded_hashes["md5"] == actual_md5
            assert result.embedded_hashes["sha1"] == actual_sha1
            assert len(result.mismatch_details) == 0

    def test_embedded_hashes_mismatch_detected(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=50)
        raw_bytes = img_path.read_bytes()

        # Mock metadata returning an altered stored hash (tampered image)
        with patch.object(ForensicImageReader, "get_metadata") as mock_meta:
            mock_meta.return_value = MagicMock(
                format_type="E01",
                size_bytes=len(raw_bytes),
                stored_md5="deadbeefdeadbeefdeadbeefdeadbeef",
                stored_sha1=None,
                stored_sha256=None,
            )

            hasher = EvidenceHasher()
            result = hasher.verify_image(img_path)

            assert result.is_verified is False
            assert len(result.mismatch_details) == 1
            assert "MD5 mismatch" in result.mismatch_details[0]

    def test_partition_discovery_inclusion(self, tmp_path):
        img_path = create_synthetic_gpt_image(tmp_path)
        hasher = EvidenceHasher()

        # 1. With partition enumeration enabled
        result_with_parts = hasher.verify_image(img_path, enumerate_partitions=True)
        assert len(result_with_parts.partitions) >= 2
        allocated = [p for p in result_with_parts.partitions if p.is_allocated]
        assert len(allocated) == 2
        assert allocated[0].description == "Windows_Evidence"
        assert allocated[1].description == "Linux_Root"

        # 2. With partition enumeration disabled
        result_no_parts = hasher.verify_image(img_path, enumerate_partitions=False)
        assert len(result_no_parts.partitions) == 0

    def test_cancellation_during_streaming(self, tmp_path):
        # Create a larger image (500 sectors = 256KB)
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=500)
        cancel_evt = threading.Event()

        # Small 1KB chunks so we can cancel in-flight
        hasher = EvidenceHasher(chunk_size=1024, cancel_event=cancel_evt)

        def on_progress(p: HashProgress):
            if p.bytes_processed >= 2048:
                hasher.cancel()

        result = hasher.verify_image(img_path, progress_callback=on_progress)
        assert result.cancelled is True
        assert result.is_verified is False
        assert "cancelled" in result.error.lower()


# ---------------------------------------------------------------------------
# Test Cases for EvidenceIntakeWorker (PySide6 QRunnable & Fallback)
# ---------------------------------------------------------------------------
class TestEvidenceIntakeWorker:
    """Verifies Qt background worker integration, signals, and headless execution."""

    def test_worker_run_success_signals(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=100)
        worker = EvidenceIntakeWorker(img_path, chunk_size=8 * 1024)

        progress_history = []
        finished_results = []
        errors = []

        worker.signals.progress.connect(
            lambda pct, speed, proc, tot: progress_history.append((pct, speed, proc, tot))
        )
        worker.signals.finished.connect(lambda res: finished_results.append(res))
        worker.signals.error.connect(lambda err: errors.append(err))

        worker.run()

        assert len(errors) == 0
        assert len(finished_results) == 1
        res = finished_results[0]
        assert isinstance(res, IntakeVerificationResult)
        assert res.is_verified is True
        assert len(res.hashes["sha256"]) == 64
        assert len(progress_history) > 0

    def test_worker_cancellation_signal(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=200)
        worker = EvidenceIntakeWorker(img_path, chunk_size=512)

        cancelled_events = []
        finished_results = []

        def on_prog(pct, speed, proc, tot):
            if proc >= 1024:
                worker.cancel()

        worker.signals.progress.connect(on_prog)
        worker.signals.cancelled.connect(lambda: cancelled_events.append(True))
        worker.signals.finished.connect(lambda res: finished_results.append(res))

        worker.run()

        assert len(cancelled_events) == 1
        assert len(finished_results) == 0

    def test_worker_error_signal_on_missing_file(self, tmp_path):
        nonexistent = tmp_path / "missing_evidence.raw"
        worker = EvidenceIntakeWorker(nonexistent)

        errors = []
        worker.signals.error.connect(lambda err: errors.append(err))
        worker.run()

        assert len(errors) == 1
        assert "not found" in errors[0].lower()

    def test_headless_fallback_worker(self, tmp_path):
        """Simulates environment where PySide6 is not imported."""
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=100)

        from app.core.intake_worker import FallbackIntakeWorker, FallbackWorkerSignals

        signals = FallbackWorkerSignals()
        received = []
        signals.finished.connect(lambda obj: received.append(obj))
        signals.finished.emit("test_result")
        assert received == ["test_result"]

        # Test running FallbackIntakeWorker
        fallback_worker = FallbackIntakeWorker(img_path, chunk_size=8 * 1024)
        finished_results = []
        fallback_worker.signals.finished.connect(lambda res: finished_results.append(res))
        fallback_worker.run()
        assert len(finished_results) == 1
        assert finished_results[0].is_verified is True
