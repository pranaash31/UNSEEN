"""
Unit Tests for RFC 3161 Trusted Timestamping (TSA) & Merkle Anchoring
Department 1: Cyber Triage & Evidence Ingestion (SIH1744 / NIA Specification)
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.core.custody_ledger import CustodyAction, CustodyLedger, OfficerIdentity
from app.core.tsa_client import RFC3161Client, RFC3161TimestampToken, request_tsa_timestamp


class TestRFC3161Client:
    """Verifies ASN.1 request creation, response parsing, and cryptographic verification."""

    def test_create_and_parse_offline_token(self):
        client = RFC3161Client()
        dummy_root = "d1e3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        # Create locally certified token for air-gapped lab environment
        token = client.create_offline_token(dummy_root, lab_authority_name="NIA-CFL-Local-TSA")

        assert isinstance(token, RFC3161TimestampToken)
        assert token.stamped_hash == dummy_root
        assert "Z" in token.tsa_gen_time_utc
        assert "+05:30" in token.tsa_gen_time_ist
        assert token.is_offline_simulated is True
        assert token.serial_number > 0
        assert len(token.token_der_b64) > 0

        # Mathematical verification of root inclusion in token
        assert token.verify(dummy_root) is True
        assert token.verify("0000000000000000000000000000000000000000000000000000000000000000") is False

        # Text output formatting
        cert_text = token.to_text()
        assert "RFC 3161 TRUSTED TIME-STAMP CERTIFICATE" in cert_text
        assert "NIA-CFL-Local-TSA" in cert_text
        assert "CRYPTOGRAPHICALLY CERTIFIED" in cert_text

    def test_create_request_asn1_encoding(self):
        client = RFC3161Client()
        sample_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        req_der = client.create_request(sample_hash, nonce=123456789)

        assert isinstance(req_der, bytes)
        assert len(req_der) > 50

        # Invalid hash lengths raise ValueError
        with pytest.raises(ValueError):
            client.create_request("short_hash")

    def test_convenience_wrapper_offline_fallback(self):
        sample_hash = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        # Force fallback by specifying invalid/unreachable URL
        token = request_tsa_timestamp(
            hash_to_stamp_hex=sample_hash,
            tsa_url="http://unreachable.invalid.local:9999/tsr",
            timeout=0.5,
            fallback_offline=True,
        )
        assert token.is_offline_simulated is True
        assert token.verify(sample_hash) is True


class TestCustodyLedgerTSAAnchoring:
    """Verifies anchoring terminal Merkle roots to RFC 3161 TSAs in the custody ledger."""

    def test_anchor_merkle_root_tsa_integration(self, tmp_path):
        ledger_file = tmp_path / "custody_chain.json"
        officer = OfficerIdentity.generate("NIA-TSA-01", "DySP Kapoor")
        ledger = CustodyLedger(ledger_file, default_officer=officer)

        # Record intake and scan
        ledger.record_action(CustodyAction.EVIDENCE_INTAKE, {"disk": "Samsung 980 Pro 1TB"})
        ledger.record_action(CustodyAction.SCAN_COMPLETED, {"findings": "2 Suspicious Autoruns"})

        # Anchor terminal Merkle root via TSA (fast offline fallback for tests)
        token = ledger.anchor_merkle_root_tsa(timeout=0.1, fallback_offline=True)

        assert isinstance(token, RFC3161TimestampToken)
        assert token.stamped_hash == ledger.entries[-2].merkle_root
        assert ledger.tsa_token is not None

        # Verify chain now recognizes and validates the TSA anchor
        ver = ledger.verify_chain()
        assert ver.is_valid is True
        assert ver.tsa_verified is True
        assert ver.tsa_certified_time is not None

        # Verify court audit trail displays external TSA anchor
        text_audit = ledger.export_court_audit_trail(format="text")
        assert "EXTERNAL RFC 3161 TRUSTED TIME-STAMP ANCHOR:" in text_audit
        assert "CRYPTOGRAPHICALLY CERTIFIED (Pre-existence Proven)" in text_audit
        assert "System clock manipulation defense refuted" in text_audit

        # Markdown audit trail
        md_audit = ledger.export_court_audit_trail(format="markdown")
        assert "RFC 3161 TSA Certified Time:" in md_audit
        assert "CERTIFIED & ANCHORED" in md_audit

        # JSON audit trail
        json_audit = ledger.export_court_audit_trail(format="json")
        doc = json.loads(json_audit)
        assert doc["audit_verification"]["tsa_verified"] is True
        assert doc["tsa_anchor"] is not None

    def test_tsa_anchor_persists_across_reloads(self, tmp_path):
        ledger_file = tmp_path / "custody_chain.json"
        ledger1 = CustodyLedger(ledger_file)
        ledger1.record_action(CustodyAction.EVIDENCE_INTAKE, {"device": "USB 32GB"})
        token1 = ledger1.anchor_merkle_root_tsa(timeout=0.1, fallback_offline=True)

        # Reload from disk
        ledger2 = CustodyLedger(ledger_file)
        assert ledger2.tsa_token is not None
        assert ledger2.tsa_token.stamped_hash == token1.stamped_hash
        assert ledger2.tsa_token.serial_number == token1.serial_number

        ver2 = ledger2.verify_chain()
        assert ver2.is_valid is True
        assert ver2.tsa_verified is True
