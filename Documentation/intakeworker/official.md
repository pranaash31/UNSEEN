1. Objective
    To verify the integrity of imported forensic images, calculate cryptographic hashes, identify disk partitions, and automatically generate statutory admissibility certificates under Section 63(4) of the Bharatiya Sakshya Adhiniyam (BSA), 2023 before downstream forensic analysis.

2. Key Concepts
    - QRunnable: Executes tasks in the background without freezing the application.
    - QThreadPool: Manages background threads.
    - Chunk Streaming: Reads large disk images in smaller 8 MB blocks to reduce RAM usage.
    - Cryptographic Hashing: Generates digital fingerprints using SHA-256, SHA-1 and MD5 in a single pass.
    - Hash Comparison: Compares calculated hashes with original acquisition hashes to detect tampering or corruption.
    - MB/s Monitoring: Tracks throughput and calculates remaining processing time.
    - Cancellation: Allows investigators to safely stop ongoing processing without data corruption.
    - BSA Section 63(4) Statutory Compliance: Automates the generation of the mandatory two-part certificate (Part A Custodian + Part B Forensic Expert) replacing Section 65B of the Indian Evidence Act.
    - Blockchain & Merkle Hash Chain: Cryptographically links every investigative action into an append-only ledger (`custody_chain.json`) with Ed25519 digital signatures and Lightweight Merkle Inclusion Proofs.

3. Internal Working
    1. Investigator imports a RAW or E01 forensic image.
    2. QRunnable processes the image in a background thread.
    3. The image is read in 8 MB chunks while calculating three hashes simultaneously (SHA-256, SHA-1, MD5).
    4. Calculated hashes are compared with recorded acquisition hashes.
    5. MBR/GPT partition information is discovered.
    6. Results are packaged into an IntakeVerificationResult report.
    7. Statutory BSA Section 63(4) Manifest is generated in text, markdown, and JSON formats for court submission.
    8. The intake action is cryptographically signed and appended to `custody_chain.json`.

4. Expected Outcome
    - Detects potential image corruption or modification.
    - Prevents application freezing during multi-gigabyte/terabyte image processing.
    - Minimizes memory consumption through 8 MB streaming blocks.
    - Identifies disk partitions and filesystem types.
    - Automatically outputs court-ready certificates under BSA Section 63(4) to eliminate evidentiary challenges in judicial proceedings.
    - Enables lightweight selective disclosure via Merkle Inclusion Proofs without revealing unrelated classified case data.

5. Legal Admissibility in Indian Courts (BSA Section 63(4))
    - Under Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 (which replaced Section 65B of the Indian Evidence Act, 1872), electronic evidence is inadmissible unless accompanied by a statutory two-part certificate:
      - Part A (Signed by Custodian / Seizing Officer): Details device make, model, serial number/IMEI, custody timeline, and affirms no tampering occurred during lawful custody.
      - Part B (Signed by Forensic Expert / Examiner): Records forensic bit-stream imaging tools, acquisition media size, cryptographic hash values (SHA-256, SHA-1, MD5), partition layouts, and certifies integrity against acquisition baselines.
    - Automating this manifest at intake eliminates manual transcription errors in 64-character SHA-256 strings, saves hours of paperwork for NIA officers, and establishes an airtight chain-of-custody.

6. Unbroken Chain of Custody, Officer Signatures & Merkle Proofs (custody_ledger.py)
    - **Defense Challenge:** In high-profile counter-terror trials, defense attorneys routinely allege that digital evidence was planted, altered, or manipulated while in police custody, or that unauthorized officers tampered with the case files.
    - **Cryptographic Solution:** UNSEEN builds an append-only SHA-256 Merkle hash chain saved to `custody_chain.json` with integrated Ed25519 asymmetric digital signatures.
    - **Officer Digital Signatures (Ed25519 Non-Repudiation):**
      - Each investigating officer holds a private/public Ed25519 keypair (`OfficerIdentity`).
      - Every action in the custody chain is digitally signed with the officer's private key over the block header hash.
      - The officer's 32-byte public key (`officer_public_key`) and 64-byte signature (`signature`) are permanently embedded in the block.
      - `verify_chain()` mathematically verifies the Ed25519 signature on every block, legally proving non-repudiation.
    - **Lightweight Merkle Inclusion Proofs (SPV / Selective Disclosure):**
      - Investigators can generate a standalone cryptographic certificate (`generate_merkle_proof(block_index)`).
      - Contains the logarithmic sibling audit path proving a specific seized artifact or evidence block belongs to the terminal Merkle root.
      - Enables sharing mathematical proof with special courts, foreign counter-terror agencies (Interpol/MLAT), or prosecutors without disclosing other confidential or unrelated case files.
    - **Mathematical Proof:** If a single byte in `custody_chain.json`, an evidence file, an officer public key, or a signature is altered post-seizure, the block hash recalculation, digital signature validation, and Merkle tree root fail immediately, pinpointing the exact altered block and preserving full court transparency.
