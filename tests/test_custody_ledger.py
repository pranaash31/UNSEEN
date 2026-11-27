"""
Unit Tests for Unbroken Chain of Custody Ledger, Officer Digital Signatures & Merkle Inclusion Proofs
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
    MerkleInclusionProof,
    OfficerIdentity,
    compute_merkle_root,
    compute_sha256,
    generate_merkle_proof_path,
    verify_merkle_proof,
)
from app.core.intake_worker import EvidenceHasher
from tests.test_image_reader import create_synthetic_mbr_image


class TestOfficerIdentity:
    """Verifies Ed25519 key generation, digital signing, and signature verification."""

    def test_generate_and_sign_verify(self):
        officer = OfficerIdentity.generate(badge_id="NIA-TEST-77", name="Inspector Sharma")
        assert officer.can_sign is True
        assert len(officer.public_key_hex) == 64  # 32 bytes hex = 64 chars

        message = "Forensic evidence block hash verification"
        signature_hex = officer.sign(message)
        assert len(signature_hex) == 128  # 64 bytes hex = 128 chars

        # Verify with own instance
        assert officer.verify(signature_hex, message) is True

        # Verify with public-only verifier instance
        verifier = OfficerIdentity.public_only(
            badge_id="NIA-TEST-77",
            name="Inspector Sharma",
            public_key_hex=officer.public_key_hex
        )
        assert verifier.can_sign is False
        assert verifier.verify(signature_hex, message) is True

        # Verify that tampered message fails
        assert verifier.verify(signature_hex, "Altered message") is False

        # Verify that corrupted signature fails
        corrupted_sig = "0" * 128
        assert verifier.verify(corrupted_sig, message) is False


class TestCustodyLedgerWithSignatures:
    """Verifies Ed25519 digital signature chaining, non-repudiation, and tamper detection."""

    def test_genesis_block_is_digitally_signed(self, tmp_path):
        ledger_file = tmp_path / "custody_chain.json"
        officer = OfficerIdentity.generate(badge_id="NIA-LEAD-01", name="SP Rajesh")
        ledger = CustodyLedger(ledger_file, default_officer=officer)

        assert ledger.length == 1
        genesis = ledger.entries[0]
        assert genesis.index == 0
        assert genesis.action == "GENESIS"
        assert genesis.officer_public_key == officer.public_key_hex
        assert len(genesis.signature) == 128
        assert genesis.previous_hash == "0" * 64
        assert len(genesis.block_hash) == 64
        assert len(genesis.merkle_root) == 64

        verification = ledger.verify_chain()
        assert verification.is_valid is True
        assert verification.total_blocks == 1
        assert verification.signatures_verified == 1

    def test_multi_officer_lifecycle_chain(self, tmp_path):
        """Tests that different officers can sign subsequent actions and all signatures verify."""
        ledger_file = tmp_path / "custody_chain.json"
        seizing_officer = OfficerIdentity.generate("DYSP-SEIZURE", "DySP Verma")
        forensic_expert = OfficerIdentity.generate("CFS-EXPERT-99", "Dr. Mehra")

        ledger = CustodyLedger(ledger_file, default_officer=seizing_officer)

        # Action 1 signed by seizing officer
        e1 = ledger.record_action(
            action=CustodyAction.EVIDENCE_INTAKE,
            details={"device": "Hard Disk 2TB", "sha256": "abc1234567890"},
            officer=seizing_officer,
        )
        assert e1.officer_public_key == seizing_officer.public_key_hex

        # Action 2 signed by forensic expert
        e2 = ledger.record_action(
            action=CustodyAction.SCAN_STARTED,
            details={"scan_type": "Memory & MFT Carving"},
            officer=forensic_expert,
        )
        assert e2.officer_public_key == forensic_expert.public_key_hex
        assert e2.previous_hash == e1.block_hash

        # Action 3 signed by forensic expert
        e3 = ledger.record_artifact_pinned(
            artifact_id="ART-MAL-01",
            artifact_type="Ransomware_Note",
            artifact_data={"filename": "DECRYPT_FILES.txt"},
            officer=forensic_expert,
        )
        assert e3.officer_public_key == forensic_expert.public_key_hex

        # Verify the multi-officer chain
        ver = ledger.verify_chain()
        assert ver.is_valid is True
        assert ver.total_blocks == 4  # Genesis + 3 actions
        assert ver.signatures_verified == 4

    def test_tamper_detection_forged_signature(self, tmp_path):
        """Verifies that tampering with an officer signature is immediately flagged."""
        ledger_file = tmp_path / "custody_chain.json"
        officer = OfficerIdentity.generate("NIA-01", "Officer A")
        ledger = CustodyLedger(ledger_file, default_officer=officer)
        ledger.record_action("TEST_ACTION", {"data": "confidential"})

        # Tamper with signature on disk
        doc = json.loads(ledger_file.read_text())
        doc["blocks"][1]["signature"] = "a" * 128
        ledger_file.write_text(json.dumps(doc))

        tampered_ledger = CustodyLedger(ledger_file)
        ver = tampered_ledger.verify_chain()
        assert ver.is_valid is False
        assert ver.broken_block_index == 1
        assert "digital signature verification failed" in ver.tamper_reason

    def test_tamper_detection_forged_public_key(self, tmp_path):
        """Verifies that substituting an officer's public key fails block hash recomputation."""
        ledger_file = tmp_path / "custody_chain.json"
        officer_real = OfficerIdentity.generate("NIA-REAL", "Real Officer")
        officer_fake = OfficerIdentity.generate("NIA-FAKE", "Fake Officer")

        ledger = CustodyLedger(ledger_file, default_officer=officer_real)
        ledger.record_action("SEIZURE", {"device": "Mobile Phone"})

        # Replace public key in block #1 with fake officer's public key
        doc = json.loads(ledger_file.read_text())
        doc["blocks"][1]["officer_public_key"] = officer_fake.public_key_hex
        ledger_file.write_text(json.dumps(doc))

        tampered_ledger = CustodyLedger(ledger_file)
        ver = tampered_ledger.verify_chain()
        assert ver.is_valid is False
        assert ver.broken_block_index == 1
        assert "block_hash recalculation failed" in ver.tamper_reason

    def test_export_court_audit_trail_includes_signatures(self, tmp_path):
        ledger_file = tmp_path / "custody_chain.json"
        officer = OfficerIdentity.generate("NIA-COURT-01", "DySP Ananya")
        ledger = CustodyLedger(ledger_file, default_officer=officer)
        ledger.record_action(CustodyAction.EVIDENCE_INTAKE, {"item": "Server Blade #4"})

        # Text audit
        txt = ledger.export_court_audit_trail(format="text")
        assert "Ed25519 Signatures   : 2 / 2 Verified" in txt
        assert "Officer Public Key :" in txt
        assert "Ed25519 Signature  :" in txt
        assert officer.public_key_hex in txt

        # Markdown audit
        md = ledger.export_court_audit_trail(format="markdown")
        assert "**Signatures Verified:** `2 / 2` (Ed25519 Non-Repudiation)" in md

        # JSON audit
        data = json.loads(ledger.export_court_audit_trail(format="json"))
        assert data["signatures_verified"] == 2
        assert "officer_public_key" in data["chain"][0]
        assert "signature" in data["chain"][0]


class TestMerkleInclusionProofs:
    """Verifies SPV-style lightweight Merkle inclusion proofs for selective disclosure."""

    def test_merkle_proof_verification_across_chain_sizes(self):
        """Tests proof generation and verification for arbitrary numbers of leaves (1..10)."""
        for count in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
            leaves = [compute_sha256(f"leaf_content_{i}") for i in range(count)]
            root = compute_merkle_root(leaves)

            for idx in range(count):
                path = generate_merkle_proof_path(leaves, idx)
                assert verify_merkle_proof(leaves[idx], path, root) is True

    def test_generate_and_verify_proof_from_custody_ledger(self, tmp_path):
        """Verifies generating proof for an arbitrary block and checking inclusion without other blocks."""
        ledger_file = tmp_path / "custody_chain.json"
        officer = OfficerIdentity.generate("NIA-EVIDENCE-07", "Inspector Roy")
        ledger = CustodyLedger(ledger_file, default_officer=officer)

        # Record 4 distinct actions: Genesis (0), Intake (1), Scan (2), Pinned (3), Report (4)
        ledger.record_action(CustodyAction.EVIDENCE_INTAKE, {"disk": "WD 1TB"})
        ledger.record_action(CustodyAction.SCAN_STARTED, {"modules": ["EVTX"]})
        pinned_entry = ledger.record_artifact_pinned(
            artifact_id="IOC-TERROR-C2",
            artifact_type="IPv4_C2",
            artifact_data={"ip": "198.51.100.44", "port": 443},
            reason="Confirmed C2 beacon from terror operative laptop"
        )
        ledger.record_action(CustodyAction.REPORT_EXPORTED, {"format": "PDF"})

        assert ledger.length == 5
        terminal_root = ledger.current_merkle_root

        # Generate lightweight Merkle inclusion proof for Block #3 (Pinned Artifact)
        proof = ledger.generate_merkle_proof(block_index=3)

        assert isinstance(proof, MerkleInclusionProof)
        assert proof.block_index == 3
        assert proof.action == "ARTIFACT_PINNED"
        assert proof.leaf_hash == pinned_entry.block_hash
        assert proof.merkle_root == terminal_root
        assert proof.total_leaves == 5
        assert len(proof.audit_path) > 0

        # 1. Self-contained mathematical verification
        assert proof.verify() is True
        assert ledger.verify_merkle_proof(proof) is True

        # 2. Officer signature verification on this single block
        assert proof.verify_signature() is True

        # 3. Text output contains court certificate headers
        txt_cert = proof.to_text()
        assert "LIGHTWEIGHT MERKLE INCLUSION PROOF" in txt_cert
        assert "MATHEMATICALLY VERIFIED (Included)" in txt_cert
        assert "CRYPTOGRAPHICALLY VERIFIED" in txt_cert
        assert "IOC-TERROR-C2" not in txt_cert  # Payload details are not exposed in minimal proof!

        # 4. JSON export
        p_dict = proof.to_dict()
        assert p_dict["block_index"] == 3
        assert p_dict["leaf_hash"] == pinned_entry.block_hash

    def test_merkle_proof_tamper_detection(self, tmp_path):
        """Verifies that tampered leaves, altered siblings, or wrong roots fail verification."""
        ledger_file = tmp_path / "custody_chain.json"
        ledger = CustodyLedger(ledger_file)
        ledger.record_action("ACTION_A", {"a": 1})
        ledger.record_action("ACTION_B", {"b": 2})

        proof = ledger.generate_merkle_proof(block_index=1)
        assert proof.verify() is True

        # Altering leaf hash
        tampered_proof = MerkleInclusionProof(
            block_index=proof.block_index,
            leaf_hash="deadbeef" * 8,
            merkle_root=proof.merkle_root,
            total_leaves=proof.total_leaves,
            audit_path=proof.audit_path,
            action=proof.action,
            timestamp_ist=proof.timestamp_ist,
            officer_badge_id=proof.officer_badge_id,
            officer_name=proof.officer_name,
            officer_public_key=proof.officer_public_key,
            signature=proof.signature,
        )
        assert tampered_proof.verify() is False

        # Testing against wrong root
        assert proof.verify(expected_root="1" * 64) is False

        # Altering sibling hash in audit path
        corrupted_path = [(h, d) if i != 0 else ("0" * 64, d) for i, (h, d) in enumerate(proof.audit_path)]
        tampered_path_proof = MerkleInclusionProof(
            block_index=proof.block_index,
            leaf_hash=proof.leaf_hash,
            merkle_root=proof.merkle_root,
            total_leaves=proof.total_leaves,
            audit_path=corrupted_path,
            action=proof.action,
            timestamp_ist=proof.timestamp_ist,
            officer_badge_id=proof.officer_badge_id,
            officer_name=proof.officer_name,
            officer_public_key=proof.officer_public_key,
            signature=proof.signature,
        )
        assert tampered_path_proof.verify() is False

    def test_out_of_bounds_proof_generation(self, tmp_path):
        ledger_file = tmp_path / "custody_chain.json"
        ledger = CustodyLedger(ledger_file)
        with pytest.raises(IndexError):
            ledger.generate_merkle_proof(block_index=99)
        with pytest.raises(IndexError):
            ledger.generate_merkle_proof(block_index=-1)
