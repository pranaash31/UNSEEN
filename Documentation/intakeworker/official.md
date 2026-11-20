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

3. Internal Working
    1. Investigator imports a RAW or E01 forensic image.
    2. QRunnable processes the image in a background thread.
    3. The image is read in 8 MB chunks while calculating three hashes simultaneously (SHA-256, SHA-1, MD5).
    4. Calculated hashes are compared with recorded acquisition hashes.
    5. MBR/GPT partition information is discovered.
    6. Results are packaged into an IntakeVerificationResult report.
    7. Statutory BSA Section 63(4) Manifest is generated in text, markdown, and JSON formats for court submission.

4. Expected Outcome
    - Detects potential image corruption or modification.
    - Prevents application freezing during multi-gigabyte/terabyte image processing.
    - Minimizes memory consumption through 8 MB streaming blocks.
    - Identifies disk partitions and filesystem types.
    - Automatically outputs court-ready certificates under BSA Section 63(4) to eliminate evidentiary challenges in judicial proceedings.

5. Legal Admissibility in Indian Courts (BSA Section 63(4))
    - Under Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 (which replaced Section 65B of the Indian Evidence Act, 1872), electronic evidence is inadmissible unless accompanied by a statutory two-part certificate:
      - Part A (Signed by Custodian / Seizing Officer): Details device make, model, serial number/IMEI, custody timeline, and affirms no tampering occurred during lawful custody.
      - Part B (Signed by Forensic Expert / Examiner): Records forensic bit-stream imaging tools, acquisition media size, cryptographic hash values (SHA-256, SHA-1, MD5), partition layouts, and certifies integrity against acquisition baselines.
    - Automating this manifest at intake eliminates manual transcription errors in 64-character SHA-256 strings, saves hours of paperwork for NIA officers, and establishes an airtight chain-of-custody.
