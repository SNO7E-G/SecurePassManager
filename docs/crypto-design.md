# Cryptographic Design Document

## Overview

SecurePassManager employs multiple layers of defense to protect user credentials, with a strong emphasis on modern cryptographic algorithms and techniques. This document outlines the cryptographic design choices made in the application.

## Encryption Architecture

### Data at Rest

All sensitive data stored by SecurePassManager is encrypted using the following approach:

1. **Database Encryption**: The entire SQLite database file is encrypted using SQLite's native encryption extension.
2. **Password Entry Encryption**: Each password entry is individually encrypted before being stored in the database, providing an additional layer of security.

### Key Management

SecurePassManager employs a hierarchical key management system:

1. **Master Password**: The user-provided master password is never stored directly.
2. **Master Key**: Derived from the master password using Argon2id.
3. **Database Key**: A separate key used for database encryption, protected by the master key.
4. **Record Keys**: Individual encryption keys for each password entry, protected by the master key.

## Cryptographic Algorithms

### Key Derivation

- **Primary**: Argon2id with tunable parameters (iterations, memory, parallelism)
- **Fallback**: PBKDF2-HMAC-SHA512 with high iteration count (minimum 310,000)

### Symmetric Encryption

- **Primary**: AES-256-GCM (Authenticated Encryption with Associated Data)
- **Secondary** (if available): ChaCha20-Poly1305
- **Alternatives** (with appropriate libraries): XChaCha20-Poly1305, Twofish, Serpent

### Hashing

- **For Verification**: SHA-512, BLAKE2b
- **For Indexing/Search**: HMAC-SHA-256 with separate key

### Random Number Generation

- **Source**: Operating system's secure random number generator (CryptGenRandom on Windows, /dev/urandom on Unix-like systems)
- **Through**: OpenSSL's RAND_bytes() function

## Authentication Mechanisms

1. **Master Password Verification**: The master password is verified using a key derivation function and a stored verification hash.
2. **Vault Integrity**: The vault's integrity is verified upon opening using HMAC signature.
3. **Authentication Tags**: Every encrypted item contains an authentication tag to detect tampering.

## Protocol Security Features

### Key Derivation Parameters

- Memory: Minimum 64MB (adjustable based on hardware)
- Iterations: Minimum 3 passes (adjustable)
- Parallelism: Based on CPU cores (default 4)
- Salt: 16 bytes of cryptographically secure random data

### Encryption Parameters

- IV/Nonce: 12 bytes of cryptographically secure random data, never reused
- Authentication Tag: 16 bytes
- Associated Data: Includes metadata such as last-modified timestamps

## Secure Channel Management

1. **Memory Protection**: All sensitive data in memory is protected against memory dumps:
   - Memory locking (mlock/VirtualLock) to prevent swapping
   - Secure allocation and wiping routines
   - Protection against cold boot attacks where possible

2. **Secure Input/Output**:
   - Screen masking of sensitive fields
   - Clipboard timeout for password safety
   - Secure memory handling for user input

## Countermeasures

1. **Against Brute Force Attacks**: 
   - Compute-intensive key derivation
   - Optional rate limiting

2. **Against Side-Channel Attacks**:
   - Constant-time comparison for sensitive operations
   - Avoidance of data-dependent branching in cryptographic code

3. **Against Memory Attacks**:
   - Secure wiping of sensitive data from memory
   - Minimizing the lifetime of unencrypted secrets in memory

## Security Validation

1. **Testing**: Comprehensive testing against known attack vectors.
2. **Verification**: Consistent use of authenticated encryption to verify data integrity.
3. **Audit**: Periodic internal security reviews and optionally external security audits.

## Future Enhancements

1. **Hardware Security Modules**: Support for hardware key storage.
2. **Post-Quantum Readiness**: Preparation for post-quantum cryptography.
3. **Biometric Integration**: Secure integration with biometric authentication systems. 