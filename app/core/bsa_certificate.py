"""
Bharatiya Sakshya Adhiniyam (BSA), 2023 - Section 63(4) Certificate Generator
Department 1: Cyber Triage & Evidence Ingestion (SIH1744 / NIA Specification)

Generates statutory two-part electronic evidence admissibility certificates
(Part A: Custodian / Officer in Charge, Part B: Forensic Expert / Cyber Examiner)
mandated under Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 (formerly Section 65B IEA).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .intake_worker import IntakeVerificationResult


# ---------------------------------------------------------------------------
# Data Models for Statutory Certificate
# ---------------------------------------------------------------------------
@dataclass
class BSACaseDetails:
    """Legal jurisdiction, case number, and agency metadata."""
    case_number: str = "NIA/RC-01/2026/NIA/DLI"
    fir_number: Optional[str] = "RC-01/2026/NIA/DLI"
    police_station: str = "NIA Police Station, New Delhi"
    investigating_agency: str = "National Investigation Agency (NIA)"
    division: str = "Anti-Cyber Terrorism Division"
    court_name: str = "Special NIA Court, Patiala House Courts, New Delhi"
    date_of_seizure: Optional[str] = None


@dataclass
class BSACustodianDetails:
    """Part A: Custodian / Seizing Officer particulars and chain-of-custody affirmation."""
    officer_name: str = "Authorized Investigating Officer"
    designation: str = "Deputy Superintendent of Police (Dy SP) / Inspector"
    badge_number: Optional[str] = None
    agency: str = "National Investigation Agency"
    custody_location: str = "NIA Malkhana / Evidence Vault"
    device_make: str = "Unknown"
    device_model: str = "Unknown"
    device_serial_number: str = "Unknown"
    imei_or_mac: Optional[str] = None
    custody_start_date: Optional[str] = None
    custody_end_date: Optional[str] = None


@dataclass
class BSAExpertDetails:
    """Part B: Forensic Examiner particulars and lab certification."""
    examiner_name: str = "Special Forensic Cyber Examiner"
    designation: str = "Senior Scientific Officer (Cyber Forensics)"
    laboratory: str = "NIA Cyber Forensic Laboratory (CFL)"
    agency: str = "National Investigation Agency"
    tools_used: str = "UNSEEN Cyber Triage Engine (ForensicImageReader / pyewf / pytsk3)"


@dataclass
class BSACertificate:
    """Complete statutory certificate under Section 63(4) of BSA, 2023."""
    certificate_id: str
    generated_at_utc: str
    case: BSACaseDetails
    custodian: BSACustodianDetails
    expert: BSAExpertDetails
    verification: IntakeVerificationResult
    is_tamper_free: bool
    statutory_act: str = "Bharatiya Sakshya Adhiniyam, 2023 (Section 63(4))"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes certificate to structured dictionary."""
        return {
            "certificate_id": self.certificate_id,
            "statutory_act": self.statutory_act,
            "generated_at_utc": self.generated_at_utc,
            "is_tamper_free": self.is_tamper_free,
            "case": asdict(self.case),
            "custodian": asdict(self.custodian),
            "expert": asdict(self.expert),
            "evidence": {
                "image_path": str(self.verification.image_path),
                "format_type": self.verification.format_type,
                "total_bytes": self.verification.total_bytes,
                "computed_hashes": self.verification.hashes,
                "embedded_hashes": self.verification.embedded_hashes,
                "is_verified": self.verification.is_verified,
                "mismatch_details": self.verification.mismatch_details,
                "partitions_count": len(self.verification.partitions),
                "partitions": [
                    {
                        "slot": p.slot,
                        "description": p.description,
                        "filesystem": p.filesystem_type,
                        "start_sector": p.start_sector,
                        "byte_offset": p.byte_offset,
                        "size_bytes": p.size_bytes,
                        "is_allocated": p.is_allocated,
                    }
                    for p in self.verification.partitions
                ],
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes certificate to machine-readable JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_text(self) -> str:
        """
        Renders the certificate in statutory court-admissible plain text format,
        ready for printing and physical signing by Custodian and Expert.
        """
        lines = [
            "=" * 84,
            "    CERTIFICATE UNDER SECTION 63(4) OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023",
            "                  (MANDATORY FOR ADMISSIBILITY OF ELECTRONIC EVIDENCE)",
            "=" * 84,
            f"Certificate Reference ID : {self.certificate_id}",
            f"Statutory Provision      : Section 63(4), Bharatiya Sakshya Adhiniyam, 2023",
            f"Generated Date (UTC)     : {self.generated_at_utc}",
            f"Integrity Status         : {'VERIFIED & UNTAMPERED' if self.is_tamper_free else 'INTEGRITY WARNING / MISMATCH'}",
            "-" * 84,
            "CASE PARTICULARS:",
            f"  Case / RC Number       : {self.case.case_number}",
            f"  FIR Reference          : {self.case.fir_number or 'N/A'}",
            f"  Investigating Agency   : {self.case.investigating_agency} ({self.case.division})",
            f"  Police Station         : {self.case.police_station}",
            f"  Adjudicating Court     : {self.case.court_name}",
            f"  Date of Seizure        : {self.case.date_of_seizure or 'As recorded in Seizure Memo'}",
            "",
            "=" * 84,
            "PART A: CERTIFICATE BY THE PERSON IN CHARGE / CUSTODIAN OF THE ELECTRONIC DEVICE",
            "=" * 84,
            "1. IDENTIFICATION OF THE ELECTRONIC DEVICE / MEDIA:",
            f"   - Seized Evidence File : {self.verification.image_path.name}",
            f"   - Container Format     : {self.verification.format_type}",
            f"   - Media Capacity       : {self.verification.total_bytes:,} bytes ({self.verification.total_bytes / (1024*1024):.2f} MB)",
            f"   - Device Make / Model  : {self.custodian.device_make} / {self.custodian.device_model}",
            f"   - Serial No / IMEI/MAC : {self.custodian.device_serial_number} {f'(IMEI/MAC: {self.custodian.imei_or_mac})' if self.custodian.imei_or_mac else ''}",
            f"   - Custody Location     : {self.custodian.custody_location}",
            "",
            "2. DECLARATION OF LAWFUL CUSTODY AND OPERATING INTEGRITY:",
            "   I hereby solemnly affirm and state under Section 63(4)(a) of the Bharatiya",
            "   Sakshya Adhiniyam, 2023 that:",
            "   a. The electronic device/storage medium described above was seized and retained",
            "      under my lawful custody in connection with the investigation of the above case.",
            "   b. During the period it remained under my management and control, the said device/",
            "      storage media was kept securely, and no unauthorized person had access to it.",
            "   c. The digital data has not been altered, manipulated, or tampered with, and the",
            "      original contents remain strictly preserved in their original state.",
            "",
            "PART A SIGNATORY:",
            f"   Name of Officer        : {self.custodian.officer_name}",
            f"   Designation            : {self.custodian.designation}",
            f"   Agency / Unit          : {self.custodian.agency}",
            f"   Badge / ID Number      : {self.custodian.badge_number or 'N/A'}",
            "   Signature & Official Seal: __________________________________________",
            "   Date & Place           : __________________________________________",
            "",
            "=" * 84,
            "PART B: CERTIFICATE BY THE FORENSIC EXPERT / CYBER EXAMINER",
            "=" * 84,
            "1. TECHNICAL FORENSIC ACQUISITION & INTEGRITY VERIFICATION:",
            f"   - Evidence Image Path  : {self.verification.image_path}",
            f"   - Acquisition Tool     : {self.expert.tools_used}",
            f"   - Acquisition Size     : {self.verification.total_bytes:,} bytes",
            "   - Cryptographic Hash Manifest (Computed in a Single Uncompressed Pass):",
            f"       * SHA-256 : {self.verification.hashes.get('sha256', 'N/A')}",
            f"       * SHA-1   : {self.verification.hashes.get('sha1', 'N/A')}",
            f"       * MD5     : {self.verification.hashes.get('md5', 'N/A')}",
            "",
        ]

        if self.verification.embedded_hashes:
            lines.extend([
                "   - Embedded Acquisition Hashes (Extracted from Evidence Container Metadata):",
                f"       * SHA-256 : {self.verification.embedded_hashes.get('sha256', 'Not Recorded')}",
                f"       * SHA-1   : {self.verification.embedded_hashes.get('sha1', 'Not Recorded')}",
                f"       * MD5     : {self.verification.embedded_hashes.get('md5', 'Not Recorded')}",
                f"   - Integrity Match Check : {'PASSED (Bit-for-bit identical with acquisition)' if self.verification.is_verified else 'FAILED (Discrepancy detected)'}",
            ])
            if self.verification.mismatch_details:
                lines.append("   - Mismatch Log:")
                for m in self.verification.mismatch_details:
                    lines.append(f"       ! {m}")
        else:
            lines.append("   - Acquisition Hashes: RAW image - initial baseline hash established above.")

        lines.extend([
            "",
            f"2. PARTITION LAYOUT & VOLUME TABLE DISCOVERY ({len(self.verification.partitions)} segments identified):",
        ])

        if self.verification.partitions:
            for p in self.verification.partitions:
                alloc_tag = "ALLOCATED" if p.is_allocated else "UNALLOCATED"
                lines.append(
                    f"   [Slot {p.slot:2d}] {p.description:<30} | {p.filesystem_type:<10} | "
                    f"Start Sector: {p.start_sector:<10} | Size: {p.size_bytes:>12,} bytes | {alloc_tag}"
                )
        else:
            lines.append("   (Direct volume or unpartitioned evidence stream)")

        lines.extend([
            "",
            "3. EXPERT TECHNICAL DECLARATION:",
            "   I hereby certify under Section 63(4)(b) & (c) of the Bharatiya Sakshya Adhiniyam, 2023:",
            "   a. The cryptographic hash values detailed above were generated using certified",
            "      forensic hashing algorithms (SHA-256 / SHA-1 / MD5) across all raw data sectors.",
            "   b. The forensic duplicate is an exact, bit-for-bit bitstream representation of the",
            "      original storage device without any alteration, addition, omission, or truncation.",
            "   c. The process was conducted on a strictly write-blocked, forensic-grade workstation",
            "      ensuring complete evidentiary integrity.",
            "",
            "PART B SIGNATORY:",
            f"   Forensic Examiner      : {self.expert.examiner_name}",
            f"   Designation            : {self.expert.designation}",
            f"   Laboratory             : {self.expert.laboratory}",
            f"   Agency                 : {self.expert.agency}",
            "   Signature & Official Seal: __________________________________________",
            "   Date & Place           : __________________________________________",
            "=" * 84,
        ])

        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Renders the certificate in GitHub-flavored Markdown for documentation or reports."""
        md = [
            f"# Certificate under Section 63(4) of Bharatiya Sakshya Adhiniyam, 2023",
            f"**Statutory Provision:** Electronic Records Admissibility (Replaced Section 65B Indian Evidence Act)  ",
            f"**Certificate ID:** `{self.certificate_id}` | **Generated:** `{self.generated_at_utc}`  ",
            f"**Integrity Status:** **{'PASSED (Untampered)' if self.is_tamper_free else 'FAILED (Mismatch)'}**",
            "",
            "---",
            "## Case Particulars",
            f"- **Case / RC Number:** {self.case.case_number}",
            f"- **FIR Number:** {self.case.fir_number or 'N/A'}",
            f"- **Investigating Agency:** {self.case.investigating_agency} ({self.case.division})",
            f"- **Court:** {self.case.court_name}",
            f"- **Police Station:** {self.case.police_station}",
            "",
            "---",
            "## Part A: Certificate by Officer / Custodian",
            f"- **Custodian Officer:** {self.custodian.officer_name} ({self.custodian.designation})",
            f"- **Agency / Location:** {self.custodian.agency} — {self.custodian.custody_location}",
            f"- **Device Description:** {self.custodian.device_make} {self.custodian.device_model} (S/N: {self.custodian.device_serial_number})",
            "",
            "> [!NOTE]",
            "> *Affirmation under Sec 63(4)(a):* The device remained in lawful custody without unauthorized access, tampering, or manipulation throughout the custody period.",
            "",
            "---",
            "## Part B: Certificate by Forensic Expert / Cyber Examiner",
            f"- **Examiner:** {self.expert.examiner_name} ({self.expert.designation})",
            f"- **Laboratory:** {self.expert.laboratory}, {self.expert.agency}",
            f"- **Forensic Tool:** `{self.expert.tools_used}`",
            "",
            "### Cryptographic Hash Manifest",
            "| Algorithm | Computed Digest | Embedded Acquisition Hash | Status |",
            "| :--- | :--- | :--- | :--- |",
        ]

        for algo in ("sha256", "sha1", "md5"):
            comp = self.verification.hashes.get(algo, "N/A")
            emb = self.verification.embedded_hashes.get(algo, "Not Recorded")
            if emb != "Not Recorded":
                status = "Match" if comp.lower() == emb.lower() else "**MISMATCH**"
            else:
                status = "Baseline Created"
            md.append(f"| `{algo.upper()}` | `{comp}` | `{emb}` | {status} |")

        md.extend([
            "",
            "### Discovered Partition Table Structure",
            "| Slot | Description | Filesystem | Start Sector | Size (Bytes) | Allocated |",
            "| :---: | :--- | :--- | :---: | :---: | :---: |",
        ])

        for p in self.verification.partitions:
            md.append(f"| {p.slot} | {p.description} | {p.filesystem_type} | {p.start_sector} | {p.size_bytes:,} | {'Yes' if p.is_allocated else 'No'} |")

        md.extend([
            "",
            "---",
            "> [!IMPORTANT]",
            "> This manifest is legally admissible under Section 63(4) of BSA, 2023 when signed by the designated officer and forensic examiner.",
        ])

        return "\n".join(md)


# ---------------------------------------------------------------------------
# Generator Factory
# ---------------------------------------------------------------------------
def generate_bsa_certificate(
    verification_result: IntakeVerificationResult,
    case_details: Optional[BSACaseDetails] = None,
    custodian_details: Optional[BSACustodianDetails] = None,
    expert_details: Optional[BSAExpertDetails] = None,
    certificate_id: Optional[str] = None,
) -> BSACertificate:
    """
    Constructs a complete statutory Section 63(4) BSA certificate from an IntakeVerificationResult.
    """
    cert_id = certificate_id or f"BSA63-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    case = case_details or BSACaseDetails()
    custodian = custodian_details or BSACustodianDetails()
    expert = expert_details or BSAExpertDetails()

    is_tamper_free = bool(verification_result.is_verified and not verification_result.cancelled)

    return BSACertificate(
        certificate_id=cert_id,
        generated_at_utc=gen_time,
        case=case,
        custodian=custodian,
        expert=expert,
        verification=verification_result,
        is_tamper_free=is_tamper_free,
    )
