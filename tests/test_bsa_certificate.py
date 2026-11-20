"""
Unit Tests for Bharatiya Sakshya Adhiniyam (BSA) Section 63(4) Certificate Generator
Department 1: Cyber Triage & Evidence Ingestion (SIH1744 / NIA Specification)
"""

import json
from pathlib import Path

import pytest

from app.core.bsa_certificate import (
    BSACaseDetails,
    BSACertificate,
    BSACustodianDetails,
    BSAExpertDetails,
    generate_bsa_certificate,
)
from app.core.intake_worker import EvidenceHasher
from tests.test_image_reader import create_synthetic_mbr_image


class TestBSACertificateGenerator:
    """Verifies statutory Section 63(4) BSA certificate generation, formats, and integrity."""

    def test_generate_certificate_from_verification_result(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=100)
        hasher = EvidenceHasher()
        result = hasher.verify_image(img_path)

        case = BSACaseDetails(
            case_number="NIA/RC-04/2026/NIA/DLI",
            fir_number="RC-04/2026/NIA/DLI",
            police_station="NIA PS New Delhi",
            date_of_seizure="2026-11-15",
        )
        custodian = BSACustodianDetails(
            officer_name="Inspector Rajesh Kumar",
            designation="Inspector of Police",
            agency="National Investigation Agency",
            device_make="Seagate",
            device_model="Barracuda 2TB",
            device_serial_number="WCA20269981A",
        )
        expert = BSAExpertDetails(
            examiner_name="Dr. Sunita Sharma",
            designation="Principal Cyber Forensic Scientist",
            laboratory="NIA Central Forensic Science Lab",
        )

        cert = generate_bsa_certificate(
            verification_result=result,
            case_details=case,
            custodian_details=custodian,
            expert_details=expert,
            certificate_id="BSA63-TEST-001",
        )

        assert isinstance(cert, BSACertificate)
        assert cert.certificate_id == "BSA63-TEST-001"
        assert cert.is_tamper_free is True
        assert cert.statutory_act == "Bharatiya Sakshya Adhiniyam, 2023 (Section 63(4))"

        # Check JSON export
        json_str = cert.to_json()
        data = json.loads(json_str)
        assert data["certificate_id"] == "BSA63-TEST-001"
        assert data["case"]["case_number"] == "NIA/RC-04/2026/NIA/DLI"
        assert data["custodian"]["device_serial_number"] == "WCA20269981A"
        assert data["expert"]["examiner_name"] == "Dr. Sunita Sharma"
        assert "sha256" in data["evidence"]["computed_hashes"]
        assert len(data["evidence"]["partitions"]) >= 1

        # Check Court Text format
        text_output = cert.to_text()
        assert "CERTIFICATE UNDER SECTION 63(4) OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023" in text_output
        assert "PART A: CERTIFICATE BY THE PERSON IN CHARGE / CUSTODIAN" in text_output
        assert "PART B: CERTIFICATE BY THE FORENSIC EXPERT / CYBER EXAMINER" in text_output
        assert "Inspector Rajesh Kumar" in text_output
        assert "Dr. Sunita Sharma" in text_output
        assert data["evidence"]["computed_hashes"]["sha256"] in text_output

        # Check Markdown format
        md_output = cert.to_markdown()
        assert "# Certificate under Section 63(4) of Bharatiya Sakshya Adhiniyam, 2023" in md_output
        assert "Inspector Rajesh Kumar" in md_output
        assert "Cryptographic Hash Manifest" in md_output

    def test_certificate_flags_tampering_or_mismatch(self, tmp_path):
        img_path = create_synthetic_mbr_image(tmp_path, sector_size=512, total_sectors=50)
        hasher = EvidenceHasher()
        # Force a mismatch via wrong expected hash
        result = hasher.verify_image(
            img_path,
            expected_hashes={"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}
        )

        cert = generate_bsa_certificate(verification_result=result)
        assert cert.is_tamper_free is False
        assert "INTEGRITY WARNING / MISMATCH" in cert.to_text()
        assert "FAILED" in cert.to_markdown()
