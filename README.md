# SHA-512 Hash Algorithm Implementation

This repository contains a Python implementation of the SHA-512 cryptographic hash algorithm. The program provides a detailed, step-by-step realization of the hashing process, highlighting the inner workings of secure hash functions. It takes an input message from a file, processes it through the SHA-512 algorithm with features like round-based processing, and produces a hexadecimal hash value as output.

---
## Key Features

- **Smart Initialization**: The algorithm starts with hash buffers and constants derived from prime numbers.
- **Padding with Purpose**: Before hashing, the input message is padded to ensure its length aligns with the block size (1024 bits). This step preserves data integrity while adhering to cryptographic standards.
- **Dynamic Message Scheduling**: An 80-word message schedule is generated, where the first 16 words come directly from the input, and the remaining 64 are calculated using clever permutations and bitwise operations.
- **80 Rounds of Processing Power**: Each 1024-bit message block undergoes 80 rounds of transformation, with intermediate hash values continually updated and refined.
- **Hex-Formatted Hash Output**: The final 512-bit hash is presented as an easy-to-read hexadecimal string.
