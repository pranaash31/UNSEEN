1. Objective
    To verify the integrity of imported forensic images, calculate cryptographic hashes, and identify disk partitions before further forensic analysis.

2. Key Concepts
- QRunnable: Executes tasks in the background without freezing the application.
- QThreadPool: Manages background threads.
- Chunk Streaming: Reads large disk images in smaller 8 MB blocks to reduce RAM usage.
- Cryptographic Hashing: Generates digital fingerprints using SHA-256, SHA-1 and MD5.
- Hash Comparison: Compares calculated hashes with original acquisition hashes to detect changes.
- MB/s Monitoring: Displays the speed of image processing.
- Cancellation: Allows investigators to stop ongoing processing.