"""
Unit Tests for Unbroken Chain of Custody Ledger (custody_ledger.py)
Department 1: Cyber Triage & Evidence Ingestion (SIH1744 / NIA Specification)
"""

import json
from pathlib import Path

import pytest

from app.core.custody_ledger import (
    CustodyAction,
    CustodyEntry,
    CustodyLedger,
    LedgerVerificationResult,
    compute_merkle_root,
    compute_sha256,
)
from app.core.intake_worker import EvidenceHasher
from tests.test_image_reader import create_synthetic_mbr_image


class TestCustodyLedger:
    """Verifies SHA-256 Merkle chain construction, action recording, persistence, and tamper detection."""

    def test_genesis_block_creation(self, tmp_path):
        ledger_file = tmp_path / "custody_chain.json"
        ledger = CustodyLedger(ledger_file, default_officer_badge_id="NIA-TEST-01")

        assert ledger.length == 1
        genesis = ledger.entries[0]
        assert genesis.index == 0
        assert genesis.action == "GENESIS"
        assert genesis.previous_hash == "0" * 64
        assert len(genesis.block_hash) == 64
        assert len(genesis.merkle_root) == 64
        assert "Z" in genesis.timestamp_utc
        assert "+05:30" in genesis.timestamp_ist
        assert ledger_file.exists()

        # Verify chain is mathematically valid
        verification = ledger.verify_chain()
        assert verification.is_valid is True
        assert verification.total_blocks == 1
        assert verification.broken_block_index is None

    def test_unbroken_lifecycle_action_chain(self, tmp_path):
        """Tests complete chain: Intake -> Scan -> Artifact Pinned -> Report Exported."""
        ledger_file = tmp_path / "custody_chain.json"
        ledger = CustodyLedger(ledger_file, default_officer_badge_id="NIA-AGENT-44")

        # 1. Evidence Intake
        e1 = ledger.record_action(
            action=CustodyAction.EVIDENCE_INTAKE,
            details={
                "image_name": "suspect_pc.E01",
                "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                "size_bytes": 10737418240,
            },
        )
        assert e1.index == 1
        assert e1.previous_hash == ledger.entries[0].block_hash

        # 2. Scan Started
        e2 = ledger.record_action(
            action=CustodyAction.SCAN_STARTED,
            details={"scan_profile": "Full Triage", "modules": ["EVTX", "Registry", "MFT"]},
        )
        assert e2.index == 2
        assert e2.previous_hash == e1.block_hash

        # 3. Artifact Pinned
        e3 = ledger.record_artifact_pinned(
            artifact_id="ART-0091",
            artifact_type="Suspicious_PowerShell",
            artifact_data={"cmd": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIA..."},
            reason="C2 beaconing behavior detected",
        )
        assert e3.index == 3
        assert e3.previous_hash == e2.block_hash

        # 4. Report Exported
        e4 = ledger.record_report_export(
            report_path=tmp_path / "NIA_Investigation_Report.pdf",
            report_format="PDF",
            report_bytes=b"MOCK_PDF_REPORT_CONTENT",
        )
        assert e4.index == 4
        assert e4.previous_hash == e3.block_hash

        assert ledger.length == 5
        verification = ledger.verify_chain()
        assert verification.is_valid is True
        assert verification.total_blocks == 5
        assert verification.merkle_root == e4.merkle_root

    def test_persistence_and_reload(self, tmp_path):
        ledger_file = tmp_path / "custody_chain.json"
        ledger1 = CustodyLedger(ledger_file, default_officer_badge_id="NIA-OFFICER-01")
        ledger1.record_action("TEST_ACTION_1", {"key": "val1"})
        ledger1.record_action("TEST_ACTION_2", {"key": "val2"})
        assert ledger1.length == 3

        # Open fresh instance pointing to same file
        ledger2 = CustodyLedger(ledger_file)
        assert ledger2.length == 3
        assert ledger2.latest_block_hash == ledger1.latest_block_hash
        assert ledger2.current_merkle_root == ledger1.current_merkle_root

        ver2 = ledger2.verify_chain()
        assert ver2.is_valid is True

    def test_tamper_detection_modified_payload(self, tmp_path):
        """Verifies that altering any detail payload breaks payload_hash and invalidates chain."""
        ledger_file = tmp_path / "custody_chain.json"
        ledger = CustodyLedger(ledger_file)
        ledger.record_action("EVIDENCE_SEIZED", {"hash": "abc", "status": "verified"})
        ledger.record_action("SCAN_COMPLETED", {"files": 4500})

        # Tamper directly with the JSON file on disk (alter files count from 4500 to 9999)
        raw_doc = json.loads(ledger_file.read_text())
        raw_doc["blocks"][2]["details"]["files"] = 9999
        ledger_file.write_text(json.dumps(raw_doc))

        # Reload tampered ledger
        tampered_ledger = CustodyLedger(ledger_file)
        ver = tampered_ledger.verify_chain()
        assert ver.is_valid is False
        assert ver.broken_block_index == 2
        assert "payload hash mismatch" in ver.tamper_reason

    def test_tamper_detection_broken_chain_pointer(self, tmp_path):
        """Verifies that modifying previous_hash breaks link continuity."""
        ledger_file = tmp_path / "custody_chain.json"
        ledger = CustodyLedger(ledger_file)
        ledger.record_action("ACTION_1", {"step": 1})
        ledger.record_action("ACTION_2", {"step": 2})

        raw_doc = json.loads(ledger_file.read_text())
        raw_doc["blocks"][2]["previous_hash"] = "deadbeef" * 8
        ledger_file.write_text(json.dumps(raw_doc))

        tampered_ledger = CustodyLedger(ledger_file)
        ver = tampered_ledger.verify_chain()
        assert ver.is_valid is False
        assert ver.broken_block_index == 2
        assert "link broken" in ver.tamper_reason

    def test_tamper_detection_modified_timestamp(self, tmp_path):
        """Verifies that modifying a timestamp invalidates block_hash."""
        ledger_file = tmp_path / "custody_chain.json"
        ledger = CustodyLedger(ledger_file)
        ledger.record_action("SEIZURE", {"device": "Laptop"})

        raw_doc = json.loads(ledger_file.read_text())
        raw_doc["blocks"][1]["timestamp_utc"] = "1999-01-01T00:00:00.000000Z"
        ledger_file.write_text(json.dumps(raw_doc))

        tampered_ledger = CustodyLedger(ledger_file)
        ver = tampered_ledger.verify_chain()
        assert ver.is_valid is False
        assert ver.broken_block_index == 1
        assert "block_hash recalculation failed" in ver.tamper_reason

    def test_merkle_root_calculation_algorithm(self):
        # Empty
        assert compute_merkle_root([]) == "0" * 64
        # Single
        h1 = compute_sha256("block_1")
        assert compute_merkle_root([h1]) == h1
        # Two
        h2 = compute_sha256("block_2")
        expected_2 = compute_sha256(h1 + h2)
        assert compute_merkle_root([h1, h2]) == expected_2
        # Three (odd -> duplicate last)
        h3 = compute_sha256("block_3")
        parent1 = compute_sha256(h1 + h2)
        parent2 = compute_sha256(h3 + h3)
        expected_3 = compute_sha256(parent1 + parent2)
        assert compute_merkle_root([h1, h2, h3]) == expected_3

    def test_export_court_audit_trail_formats(self, tmp_path):
        ledger_file = tmp_path / "custody_chain.json"
        ledger = CustodyLedger(ledger_file, default_officer_badge_id="NIA-SPECIAL-AGENT-07")
        ledger.record_action(CustodyAction.EVIDENCE_INTAKE, {"case": "RC-01/2026", "item": "Drive #1"})
        ledger.record_action(CustodyAction.REPORT_EXPORTED, {"format": "PDF"})

        # Plaintext format
        text_audit = ledger.export_court_audit_trail(format="text")
        assert "CERTIFIED UNBROKEN FORENSIC CHAIN OF CUSTODY AUDIT TRAIL" in text_audit
        assert "NIA-SPECIAL-AGENT-07" in text_audit
        assert "EVIDENCE_INTAKE" in text_audit
        assert "Terminal Merkle Root" in text_audit

        # Markdown format
        md_audit = ledger.export_court_audit_trail(format="markdown")
        assert "# UNBROKEN FORENSIC CHAIN OF CUSTODY AUDIT TRAIL" in md_audit
        assert "Section 63(4), Bharatiya Sakshya Adhiniyam, 2023" in md_audit
        assert "| # | Action | Timestamp (IST) | Officer Badge | Block Hash | Merkle Root |" in md_audit

        # JSON format
        json_audit = ledger.export_court_audit_trail(format="json")
        data = json.loads(json_audit)
        assert data["audit_verification"]["is_valid"] is True
        assert len(data["chain"]) == 3
