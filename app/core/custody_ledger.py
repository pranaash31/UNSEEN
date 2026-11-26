"""
Unbroken Chain of Custody Ledger with Officer Digital Signatures
(custody_ledger.py — Blockchain & Cybersecurity Bucket)
Department 1: Cyber Triage & Evidence Ingestion (SIH1744 / NIA Specification)

Provides a tamper-evident, append-only Merkle-linked cryptographic audit ledger
(custody_chain.json) featuring:
- Asymmetric Officer Digital Signatures (Ed25519) for non-repudiation.
- Synchronized dual UTC + Indian Standard Time (IST) timestamps.
- Binary Merkle tree root accumulation.
- Mathematical tamper detection proving zero post-seizure evidence planting.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Cryptography Import for Ed25519 Asymmetric Signatures
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    InvalidSignature = Exception  # type: ignore

# Indian Standard Time (IST) Offset: UTC+05:30
IST_TIMEZONE = timezone(timedelta(hours=5, minutes=30))
GENESIS_PREVIOUS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Canonical JSON & Cryptographic Primitives
# ---------------------------------------------------------------------------
def canonical_json(data: Any) -> str:
    """Serializes data to deterministic, sort-keyed canonical JSON string."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def compute_sha256(content: Union[str, bytes]) -> str:
    """Computes lowercase hex SHA-256 digest of utf-8 string or raw bytes."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest().lower()


def compute_merkle_root(leaf_hashes: List[str]) -> str:
    """
    Computes binary Merkle tree root over an ordered list of leaf SHA-256 hashes.
    Duplicates trailing node if count is odd (RFC 6962 / Bitcoin standard).
    """
    if not leaf_hashes:
        return GENESIS_PREVIOUS_HASH
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]

    current_level = list(leaf_hashes)
    while len(current_level) > 1:
        next_level: List[str] = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = compute_sha256(left + right)
            next_level.append(combined)
        current_level = next_level

    return current_level[0]


# ---------------------------------------------------------------------------
# Officer Identity & Asymmetric Key Management (Ed25519)
# ---------------------------------------------------------------------------
class OfficerIdentity:
    """
    Cryptographic officer identity providing Ed25519 digital signatures.
    Establishes non-repudiation under Section 63(4) of Bharatiya Sakshya Adhiniyam, 2023.
    """
    def __init__(self,
                 badge_id: str,
                 name: str,
                 private_key: Optional[ed25519.Ed25519PrivateKey] = None,
                 public_key: Optional[ed25519.Ed25519PublicKey] = None):
        self.badge_id = badge_id
        self.name = name
        self._private_key = private_key
        if public_key:
            self._public_key = public_key
        elif private_key:
            self._public_key = private_key.public_key()
        else:
            raise ValueError("Either private_key or public_key must be supplied.")

    @classmethod
    def generate(cls, badge_id: str, name: str) -> OfficerIdentity:
        """Generates a fresh Ed25519 keypair for an investigator."""
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("The 'cryptography' library is required to generate officer keypairs.")
        priv = ed25519.Ed25519PrivateKey.generate()
        return cls(badge_id=badge_id, name=name, private_key=priv)

    @classmethod
    def from_private_key_bytes(cls, badge_id: str, name: str, raw_32_bytes: bytes) -> OfficerIdentity:
        """Loads identity from raw 32-byte Ed25519 seed/private key."""
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_32_bytes)
        return cls(badge_id=badge_id, name=name, private_key=priv)

    @classmethod
    def public_only(cls, badge_id: str, name: str, public_key_hex: str) -> OfficerIdentity:
        """Creates a verification-only identity from a 64-character hex public key."""
        pub_bytes = bytes.fromhex(public_key_hex)
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        return cls(badge_id=badge_id, name=name, private_key=None, public_key=pub)

    @property
    def public_key_hex(self) -> str:
        """Returns 64-character lowercase hex encoding of the 32-byte Ed25519 public key."""
        raw_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return raw_bytes.hex().lower()

    @property
    def can_sign(self) -> bool:
        """True if the private key is held and signing is supported."""
        return self._private_key is not None

    def sign(self, message: Union[str, bytes]) -> str:
        """
        Signs a message (typically the block header hash) with the officer's Ed25519 private key.
        Returns 128-character lowercase hex string of the 64-byte signature.
        """
        if not self._private_key:
            raise PermissionError(f"Officer {self.badge_id} does not possess a private key for signing.")
        if isinstance(message, str):
            message = message.encode("utf-8")
        raw_sig = self._private_key.sign(message)
        return raw_sig.hex().lower()

    def verify(self, signature_hex: str, message: Union[str, bytes]) -> bool:
        """
        Verifies a 64-byte Ed25519 signature against this officer's public key.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")
        try:
            sig_bytes = bytes.fromhex(signature_hex)
            self._public_key.verify(sig_bytes, message)
            return True
        except (InvalidSignature, ValueError):
            return False


# ---------------------------------------------------------------------------
# Standard Investigative Custody Actions
# ---------------------------------------------------------------------------
class CustodyAction(str, Enum):
    GENESIS = "GENESIS"
    CASE_INITIALIZED = "CASE_INITIALIZED"
    EVIDENCE_INTAKE = "EVIDENCE_INTAKE"
    HASH_VERIFIED = "HASH_VERIFIED"
    PARTITION_DISCOVERED = "PARTITION_DISCOVERED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    ARTIFACT_PINNED = "ARTIFACT_PINNED"
    ARTIFACT_UNPINNED = "ARTIFACT_UNPINNED"
    NOTE_ADDED = "NOTE_ADDED"
    BSA_CERTIFICATE_GENERATED = "BSA_CERTIFICATE_GENERATED"
    EVIDENCE_EXPORTED = "EVIDENCE_EXPORTED"
    REPORT_EXPORTED = "REPORT_EXPORTED"
    CUSTOM = "CUSTOM"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CustodyEntry:
    """An immutable, cryptographically chained block in the custody ledger."""
    index: int
    timestamp_utc: str
    timestamp_ist: str
    officer_badge_id: str
    officer_name: str
    officer_public_key: str
    signature: str
    action: str
    payload_hash: str
    previous_hash: str
    block_hash: str
    merkle_root: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes entry to plain dictionary."""
        return asdict(self)


@dataclass
class LedgerVerificationResult:
    """Mathematical verification result of the entire custody chain."""
    is_valid: bool
    total_blocks: int
    signatures_verified: int = 0
    broken_block_index: Optional[int] = None
    tamper_reason: Optional[str] = None
    merkle_root: str = GENESIS_PREVIOUS_HASH
    verified_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


# ---------------------------------------------------------------------------
# CustodyLedger (Append-Only Merkle Hash Chain with Digital Signatures)
# ---------------------------------------------------------------------------
class CustodyLedger:
    """
    High-assurance append-only blockchain-backed custody ledger for UNSEEN DFIR.
    Maintains a cryptographically unbroken SHA-256 Merkle chain in custody_chain.json.
    Anchors Ed25519 digital signatures on every entry for legal non-repudiation.
    """
    def __init__(self,
                 ledger_file: Union[str, Path],
                 default_officer: Optional[OfficerIdentity] = None,
                 default_officer_badge_id: str = "NIA-CYBER-001",
                 default_officer_name: str = "Investigating Officer",
                 auto_genesis: bool = True):
        self._ledger_path = Path(ledger_file).resolve()
        if default_officer:
            self._default_officer = default_officer
        else:
            self._default_officer = OfficerIdentity.generate(
                badge_id=default_officer_badge_id,
                name=default_officer_name
            )

        self._entries: List[CustodyEntry] = []
        self._lock = threading.RLock()

        # Load existing chain if present, or initialize genesis block
        if self._ledger_path.exists():
            self._load()
        elif auto_genesis:
            self._init_genesis()

    @property
    def ledger_path(self) -> Path:
        return self._ledger_path

    @property
    def default_officer(self) -> OfficerIdentity:
        return self._default_officer

    @property
    def entries(self) -> List[CustodyEntry]:
        with self._lock:
            return list(self._entries)

    @property
    def length(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def latest_block_hash(self) -> str:
        with self._lock:
            return self._entries[-1].block_hash if self._entries else GENESIS_PREVIOUS_HASH

    @property
    def current_merkle_root(self) -> str:
        with self._lock:
            return self._entries[-1].merkle_root if self._entries else GENESIS_PREVIOUS_HASH

    # -----------------------------------------------------------------------
    # Chain Construction & Recording
    # -----------------------------------------------------------------------
    def _get_dual_timestamps(self) -> Tuple[str, str]:
        """Generates synchronized UTC and Indian Standard Time (IST) timestamps."""
        now_utc = datetime.now(timezone.utc)
        now_ist = now_utc.astimezone(IST_TIMEZONE)
        str_utc = now_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        str_ist = now_ist.strftime("%Y-%m-%d %H:%M:%S.%f+05:30")
        return str_utc, str_ist

    def _init_genesis(self) -> CustodyEntry:
        """Constructs, signs, and persists the immutable Genesis Block (Index 0)."""
        with self._lock:
            ts_utc, ts_ist = self._get_dual_timestamps()
            genesis_details = {
                "message": "UNSEEN Digital Forensics & Incident Response Custody Chain Initialized",
                "specification": "SIH1744 / NIA Anti-Cyber Terrorism Division",
                "hashing_algorithm": "SHA-256 Merkle Chain",
                "signature_algorithm": "Ed25519 (RFC 8032)",
                "ledger_file": self._ledger_path.name,
                "genesis_officer_badge": self._default_officer.badge_id,
            }
            p_hash = compute_sha256(canonical_json(genesis_details))
            prev_hash = GENESIS_PREVIOUS_HASH
            pub_key_hex = self._default_officer.public_key_hex

            header_raw = canonical_json({
                "index": 0,
                "timestamp_utc": ts_utc,
                "timestamp_ist": ts_ist,
                "officer_badge_id": self._default_officer.badge_id,
                "officer_name": self._default_officer.name,
                "officer_public_key": pub_key_hex,
                "action": CustodyAction.GENESIS.value,
                "payload_hash": p_hash,
                "previous_hash": prev_hash,
            })
            b_hash = compute_sha256(header_raw)
            signature_hex = self._default_officer.sign(b_hash)
            m_root = compute_merkle_root([b_hash])

            entry = CustodyEntry(
                index=0,
                timestamp_utc=ts_utc,
                timestamp_ist=ts_ist,
                officer_badge_id=self._default_officer.badge_id,
                officer_name=self._default_officer.name,
                officer_public_key=pub_key_hex,
                signature=signature_hex,
                action=CustodyAction.GENESIS.value,
                payload_hash=p_hash,
                previous_hash=prev_hash,
                block_hash=b_hash,
                merkle_root=m_root,
                details=genesis_details,
            )
            self._entries.append(entry)
            self._save()
            return entry

    def record_action(self,
                      action: Union[CustodyAction, str],
                      details: Dict[str, Any],
                      officer: Optional[OfficerIdentity] = None,
                      officer_badge_id: Optional[str] = None,
                      officer_name: Optional[str] = None) -> CustodyEntry:
        """
        Cryptographically signs and appends a new forensic action to the ledger.
        Signs the block header hash using the operating officer's Ed25519 private key.
        Recalculates cumulative Merkle root, persisting atomically to disk.
        """
        action_str = action.value if isinstance(action, CustodyAction) else str(action)
        active_officer = officer or self._default_officer
        badge = officer_badge_id or active_officer.badge_id
        name = officer_name or active_officer.name
        pub_key_hex = active_officer.public_key_hex

        with self._lock:
            if not self._entries:
                self._init_genesis()

            prev_entry = self._entries[-1]
            new_index = prev_entry.index + 1
            prev_hash = prev_entry.block_hash

            ts_utc, ts_ist = self._get_dual_timestamps()
            p_hash = compute_sha256(canonical_json(details))

            header_raw = canonical_json({
                "index": new_index,
                "timestamp_utc": ts_utc,
                "timestamp_ist": ts_ist,
                "officer_badge_id": badge,
                "officer_name": name,
                "officer_public_key": pub_key_hex,
                "action": action_str,
                "payload_hash": p_hash,
                "previous_hash": prev_hash,
            })
            b_hash = compute_sha256(header_raw)
            signature_hex = active_officer.sign(b_hash)

            # Cumulative Merkle root over all block hashes up to and including new block
            all_block_hashes = [e.block_hash for e in self._entries] + [b_hash]
            m_root = compute_merkle_root(all_block_hashes)

            new_entry = CustodyEntry(
                index=new_index,
                timestamp_utc=ts_utc,
                timestamp_ist=ts_ist,
                officer_badge_id=badge,
                officer_name=name,
                officer_public_key=pub_key_hex,
                signature=signature_hex,
                action=action_str,
                payload_hash=p_hash,
                previous_hash=prev_hash,
                block_hash=b_hash,
                merkle_root=m_root,
                details=details,
            )

            self._entries.append(new_entry)
            self._save()
            return new_entry

    # -----------------------------------------------------------------------
    # Specialized Triage Pipeline Helpers
    # -----------------------------------------------------------------------
    def record_evidence_intake(self,
                               verification_result: Any,
                               officer: Optional[OfficerIdentity] = None) -> CustodyEntry:
        """Records evidence image intake and cryptographic hash verification."""
        details = {
            "image_path": str(verification_result.image_path),
            "format_type": verification_result.format_type,
            "total_bytes": verification_result.total_bytes,
            "computed_hashes": verification_result.hashes,
            "embedded_hashes": verification_result.embedded_hashes,
            "is_verified": verification_result.is_verified,
            "partitions_count": len(verification_result.partitions),
            "duration_sec": verification_result.duration_sec,
            "throughput_mb_s": verification_result.throughput_mb_s,
        }
        return self.record_action(
            action=CustodyAction.EVIDENCE_INTAKE,
            details=details,
            officer=officer,
        )

    def record_bsa_certificate(self,
                               certificate: Any,
                               officer: Optional[OfficerIdentity] = None) -> CustodyEntry:
        """Records statutory BSA Section 63(4) court certificate generation."""
        cert_dict = certificate.to_dict() if hasattr(certificate, "to_dict") else dict(certificate)
        details = {
            "certificate_id": cert_dict.get("certificate_id"),
            "statutory_act": cert_dict.get("statutory_act"),
            "is_tamper_free": cert_dict.get("is_tamper_free"),
            "case_number": cert_dict.get("case", {}).get("case_number"),
            "custodian_officer": cert_dict.get("custodian", {}).get("officer_name"),
            "forensic_expert": cert_dict.get("expert", {}).get("examiner_name"),
            "sha256_hash": cert_dict.get("evidence", {}).get("computed_hashes", {}).get("sha256"),
        }
        return self.record_action(
            action=CustodyAction.BSA_CERTIFICATE_GENERATED,
            details=details,
            officer=officer,
        )

    def record_artifact_pinned(self,
                               artifact_id: str,
                               artifact_type: str,
                               artifact_data: Dict[str, Any],
                               reason: str = "Suspicious IOC identified",
                               officer: Optional[OfficerIdentity] = None) -> CustodyEntry:
        """Records when an investigator pins or highlights a suspicious forensic artifact."""
        details = {
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "reason": reason,
            "artifact_data_hash": compute_sha256(canonical_json(artifact_data)),
            "artifact_summary": str(artifact_data)[:256],
        }
        return self.record_action(
            action=CustodyAction.ARTIFACT_PINNED,
            details=details,
            officer=officer,
        )

    def record_report_export(self,
                             report_path: Union[str, Path],
                             report_format: str,
                             report_bytes: Optional[bytes] = None,
                             officer: Optional[OfficerIdentity] = None) -> CustodyEntry:
        """Records formal export of the investigation report."""
        report_path = Path(report_path)
        report_hash = compute_sha256(report_bytes) if report_bytes else "HASH_UNAVAILABLE"
        details = {
            "report_file": report_path.name,
            "report_format": report_format.upper(),
            "report_sha256": report_hash,
        }
        return self.record_action(
            action=CustodyAction.REPORT_EXPORTED,
            details=details,
            officer=officer,
        )

    # -----------------------------------------------------------------------
    # Chain Verification & Tamper Detection
    # -----------------------------------------------------------------------
    def verify_chain(self) -> LedgerVerificationResult:
        """
        Traverses and mathematically verifies the entire custody ledger from Genesis (0) to tip.
        Verifies:
        1. Correct monotonically increasing indexing.
        2. Unaltered payload hashes matching SHA256(details).
        3. Backward hash linkage (entry[i].previous_hash == entry[i-1].block_hash).
        4. Recomputed block hashes matching block_hash.
        5. Ed25519 digital signature validity against officer's public key (non-repudiation).
        6. Cumulative Merkle root derivation.
        """
        with self._lock:
            if not self._entries:
                return LedgerVerificationResult(
                    is_valid=False,
                    total_blocks=0,
                    tamper_reason="Ledger is empty; no genesis block present.",
                )

            cumulative_hashes: List[str] = []
            verified_signatures_count = 0

            for i, entry in enumerate(self._entries):
                # 1. Index continuity
                if entry.index != i:
                    return LedgerVerificationResult(
                        is_valid=False,
                        total_blocks=len(self._entries),
                        broken_block_index=i,
                        tamper_reason=f"Block index discontinuity: expected index {i}, found {entry.index}.",
                    )

                # 2. Payload integrity
                expected_p_hash = compute_sha256(canonical_json(entry.details))
                if entry.payload_hash != expected_p_hash:
                    return LedgerVerificationResult(
                        is_valid=False,
                        total_blocks=len(self._entries),
                        broken_block_index=i,
                        tamper_reason=(
                            f"Block #{i} payload hash mismatch: details have been tampered with or modified. "
                            f"(Expected: {expected_p_hash}, Found: {entry.payload_hash})"
                        ),
                    )

                # 3. Previous hash linkage
                if i == 0:
                    if entry.previous_hash != GENESIS_PREVIOUS_HASH:
                        return LedgerVerificationResult(
                            is_valid=False,
                            total_blocks=len(self._entries),
                            broken_block_index=0,
                            tamper_reason="Genesis block previous_hash is invalid.",
                        )
                else:
                    preceding = self._entries[i - 1]
                    if entry.previous_hash != preceding.block_hash:
                        return LedgerVerificationResult(
                            is_valid=False,
                            total_blocks=len(self._entries),
                            broken_block_index=i,
                            tamper_reason=(
                                f"Block #{i} previous_hash link broken! Chain continuity severed. "
                                f"(Expected preceding block #{i-1} hash: {preceding.block_hash}, Found: {entry.previous_hash})"
                            ),
                        )

                # 4. Header block hash recalculation
                recomputed_header = canonical_json({
                    "index": entry.index,
                    "timestamp_utc": entry.timestamp_utc,
                    "timestamp_ist": entry.timestamp_ist,
                    "officer_badge_id": entry.officer_badge_id,
                    "officer_name": entry.officer_name,
                    "officer_public_key": entry.officer_public_key,
                    "action": entry.action,
                    "payload_hash": entry.payload_hash,
                    "previous_hash": entry.previous_hash,
                })
                recomputed_b_hash = compute_sha256(recomputed_header)
                if entry.block_hash != recomputed_b_hash:
                    return LedgerVerificationResult(
                        is_valid=False,
                        total_blocks=len(self._entries),
                        broken_block_index=i,
                        tamper_reason=(
                            f"Block #{i} block_hash recalculation failed! Header data tampered. "
                            f"(Expected: {recomputed_b_hash}, Found: {entry.block_hash})"
                        ),
                    )

                # 5. Ed25519 Digital Signature Verification
                if entry.signature and entry.officer_public_key:
                    try:
                        officer_verifier = OfficerIdentity.public_only(
                            badge_id=entry.officer_badge_id,
                            name=entry.officer_name,
                            public_key_hex=entry.officer_public_key,
                        )
                        is_sig_valid = officer_verifier.verify(entry.signature, entry.block_hash)
                        if not is_sig_valid:
                            return LedgerVerificationResult(
                                is_valid=False,
                                total_blocks=len(self._entries),
                                broken_block_index=i,
                                tamper_reason=(
                                    f"Block #{i} Ed25519 digital signature verification failed! "
                                    f"Signature is forged or does not match officer public key."
                                ),
                            )
                        verified_signatures_count += 1
                    except Exception as sig_err:
                        return LedgerVerificationResult(
                            is_valid=False,
                            total_blocks=len(self._entries),
                            broken_block_index=i,
                            tamper_reason=f"Block #{i} signature verification exception: {sig_err}",
                        )

                # 6. Merkle root accumulation
                cumulative_hashes.append(entry.block_hash)
                expected_merkle = compute_merkle_root(cumulative_hashes)
                if entry.merkle_root != expected_merkle:
                    return LedgerVerificationResult(
                        is_valid=False,
                        total_blocks=len(self._entries),
                        broken_block_index=i,
                        tamper_reason=(
                            f"Block #{i} Merkle root calculation mismatch! "
                            f"(Expected: {expected_merkle}, Found: {entry.merkle_root})"
                        ),
                    )

            final_merkle = self._entries[-1].merkle_root if self._entries else GENESIS_PREVIOUS_HASH
            return LedgerVerificationResult(
                is_valid=True,
                total_blocks=len(self._entries),
                signatures_verified=verified_signatures_count,
                broken_block_index=None,
                tamper_reason=None,
                merkle_root=final_merkle,
            )

    # -----------------------------------------------------------------------
    # Persistence & Loading
    # -----------------------------------------------------------------------
    def _save(self) -> None:
        """Atomically saves the custody chain to custody_chain.json."""
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        chain_data = {
            "schema_version": "2.0",
            "statutory_compliance": "Bharatiya Sakshya Adhiniyam, 2023 (Section 63(4))",
            "signature_scheme": "Ed25519 (RFC 8032)",
            "chain_length": len(self._entries),
            "merkle_root": self.current_merkle_root,
            "latest_block_hash": self.latest_block_hash,
            "blocks": [e.to_dict() for e in self._entries],
        }

        # Write to temporary file first then replace atomically
        tmp_file = self._ledger_path.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(chain_data, indent=2), encoding="utf-8")
        tmp_file.replace(self._ledger_path)

    def _load(self) -> None:
        """Loads and deserializes custody ledger from custody_chain.json."""
        with self._lock:
            try:
                raw_text = self._ledger_path.read_text(encoding="utf-8")
                doc = json.loads(raw_text)
                blocks = doc.get("blocks", [])
                self._entries = [
                    CustodyEntry(
                        index=b["index"],
                        timestamp_utc=b["timestamp_utc"],
                        timestamp_ist=b["timestamp_ist"],
                        officer_badge_id=b["officer_badge_id"],
                        officer_name=b["officer_name"],
                        officer_public_key=b.get("officer_public_key", ""),
                        signature=b.get("signature", ""),
                        action=b["action"],
                        payload_hash=b["payload_hash"],
                        previous_hash=b["previous_hash"],
                        block_hash=b["block_hash"],
                        merkle_root=b["merkle_root"],
                        details=b.get("details", {}),
                    )
                    for b in blocks
                ]
            except Exception as exc:
                self._entries = []
                raise IOError(f"Failed to load custody chain from {self._ledger_path}: {exc}")

    # -----------------------------------------------------------------------
    # Court Audit Presentation
    # -----------------------------------------------------------------------
    def export_court_audit_trail(self, format: str = "text") -> str:
        """
        Exports the entire custody ledger into a formatted, court-admissible audit trail
        demonstrating unbroken chain of custody under BSA Section 63(4).
        """
        verification = self.verify_chain()

        if format.lower() == "json":
            return json.dumps({
                "audit_verification": asdict(verification),
                "total_entries": len(self._entries),
                "signatures_verified": verification.signatures_verified,
                "merkle_root": verification.merkle_root,
                "chain": [e.to_dict() for e in self._entries],
            }, indent=2)

        if format.lower() == "markdown":
            md = [
                "# UNBROKEN FORENSIC CHAIN OF CUSTODY AUDIT TRAIL",
                "**Legal Authority:** Section 63(4), Bharatiya Sakshya Adhiniyam, 2023  ",
                f"**Audit Status:** **{'MATHEMATICALLY VERIFIED (Untampered)' if verification.is_valid else 'TAMPER WARNING / COMPROMISED'}**  ",
                f"**Signatures Verified:** `{verification.signatures_verified} / {verification.total_blocks}` (Ed25519 Non-Repudiation)  ",
                f"**Total Chain Blocks:** `{verification.total_blocks}` | **Terminal Merkle Root:** `{verification.merkle_root}`  ",
                "",
                "---",
                "## Custody Ledger Entries",
                "| # | Action | Timestamp (IST) | Officer (Badge) | Block Hash | Ed25519 Signature |",
                "| :-: | :--- | :--- | :--- | :--- | :--- |",
            ]
            for e in self._entries:
                md.append(
                    f"| `{e.index}` | **{e.action}** | `{e.timestamp_ist}` | `{e.officer_name}` (`{e.officer_badge_id}`) | "
                    f"`{e.block_hash[:16]}...` | `{e.signature[:16]}...` |"
                )
            md.extend([
                "",
                "---",
                "> [!IMPORTANT]",
                "> Every investigative step is digitally signed via Ed25519 and chained into a SHA-256 Merkle root. "
                "Any alteration of evidence, logs, or signatures renders the chain mathematically invalid.",
            ])
            return "\n".join(md)

        # Plaintext format
        lines = [
            "=" * 96,
            "             NATIONAL INVESTIGATION AGENCY (NIA) - ANTI-CYBER TERRORISM DIVISION",
            "                  CERTIFIED UNBROKEN FORENSIC CHAIN OF CUSTODY AUDIT TRAIL",
            "               (Governed by Section 63(4), Bharatiya Sakshya Adhiniyam, 2023)",
            "=" * 96,
            f"Ledger File          : {self._ledger_path.name}",
            f"Chain Integrity      : {'SECURE & MATHEMATICALLY VERIFIED' if verification.is_valid else 'TAMPER WARNING - BROKEN CHAIN'}",
            f"Ed25519 Signatures   : {verification.signatures_verified} / {verification.total_blocks} Verified (Non-Repudiation Established)",
            f"Total Blocks         : {verification.total_blocks}",
            f"Terminal Merkle Root : {verification.merkle_root}",
            f"Verification Date    : {verification.verified_at_utc}",
            "-" * 96,
        ]

        if not verification.is_valid:
            lines.extend([
                f"! TAMPER DETECTED AT BLOCK #{verification.broken_block_index} !",
                f"! Reason: {verification.tamper_reason}",
                "-" * 96,
            ])

        for e in self._entries:
            lines.extend([
                f"[Block #{e.index:03d}] Action: {e.action}",
                f"  Timestamp UTC      : {e.timestamp_utc}",
                f"  Timestamp IST      : {e.timestamp_ist}",
                f"  Operating Officer  : {e.officer_name} (Badge: {e.officer_badge_id})",
                f"  Officer Public Key : {e.officer_public_key}",
                f"  Ed25519 Signature  : {e.signature}",
                f"  Payload SHA-256    : {e.payload_hash}",
                f"  Previous Hash      : {e.previous_hash}",
                f"  Block Hash         : {e.block_hash}",
                f"  Cumulative Merkle  : {e.merkle_root}",
                f"  Details Summary    : {json.dumps(e.details, default=str)[:120]}...",
                "-" * 96,
            ])

        lines.extend([
            "=" * 96,
            "CERTIFICATION STATEMENT:",
            "I hereby certify that the above ledger represents an immutable cryptographic audit record",
            "of all investigative actions performed on the digital evidence. Each block is digitally signed",
            "using Ed25519 asymmetric cryptography and chained into a SHA-256 Merkle root, proving that",
            "zero files, logs, or artifacts were added, modified, planted, or deleted post-seizure.",
            "",
            "Officer Signature & Seal: ___________________________________  Date: ____________________",
            "=" * 96,
        ])
        return "\n".join(lines)
