# Security FAQ

## General Security Questions

### How secure is SecurePassManager?

SecurePassManager is designed with security as the highest priority. It employs military-grade encryption (AES-256-GCM), modern key derivation functions (Argon2id), and multiple layers of protection for your passwords. All security-critical code undergoes rigorous review and testing. Regular security audits are conducted to ensure the highest standards are maintained.

### What encryption algorithms are used?

SecurePassManager uses AES-256 in GCM mode (Galois/Counter Mode) as the primary encryption algorithm. This provides both confidentiality and authenticity of the encrypted data. Additional algorithms may be available depending on your build configuration, including ChaCha20-Poly1305, Twofish, and Serpent.

### Is my master password stored anywhere?

No, your master password is never stored directly. Instead, we use a key derivation function (Argon2id or PBKDF2) to transform your password into cryptographic keys. Only a verification hash is stored, which allows the application to verify that you've entered the correct master password without storing the password itself.

### How does the password manager protect against brute force attacks?

SecurePassManager uses Argon2id (or PBKDF2 as a fallback) with high computational and memory requirements to derive keys from your master password. This makes brute force attacks extremely time-consuming and resource-intensive, even with specialized hardware.

### What happens if I forget my master password?

There is no way to recover your vault if you forget your master password. This is a deliberate security feature - if we could recover your passwords without the master password, it would mean potential attackers could as well. We recommend:

1. Creating a strong but memorable master password
2. Considering a secure backup solution for your master password
3. Regularly exporting an encrypted backup of your vault

## Technical Security Questions

### How does SecurePassManager protect my passwords in memory?

Several measures are taken to protect sensitive data in memory:

1. Memory locking to prevent sensitive data from being swapped to disk
2. Secure memory allocation and wiping routines
3. Minimizing the time sensitive data remains in memory
4. Protection against memory examination by other processes

### Is my clipboard protected when I copy a password?

Yes, SecurePassManager includes clipboard protection features:

1. Automatic clipboard clearing after a configurable timeout (default 30 seconds)
2. Option to use alternative methods to enter passwords without using the clipboard

### What's the difference between the database encryption and the password encryption?

SecurePassManager employs multiple encryption layers:

1. **Database encryption**: The entire database file is encrypted to protect all content
2. **Individual password encryption**: Each password entry is separately encrypted with its own key
3. **Key encryption**: All encryption keys are themselves protected by keys derived from your master password

This multi-layered approach provides defense in depth.

### How does SecurePassManager handle random number generation?

Secure random numbers are essential for cryptographic operations. SecurePassManager uses:

1. The operating system's secure random number generator (e.g., CryptGenRandom, /dev/urandom)
2. OpenSSL's RAND_bytes() function which includes additional entropy gathering
3. Proper seeding and management of randomness

### Does SecurePassManager protect against side-channel attacks?

Yes, SecurePassManager includes several protections against side-channel attacks:

1. Constant-time comparison operations for sensitive data
2. Avoidance of data-dependent branching in cryptographic code
3. Protection against timing attacks in password verification

## Privacy Questions

### Does SecurePassManager collect any data about me or my passwords?

No. SecurePassManager is designed with privacy in mind and does not collect any data about you or your passwords. The application operates entirely locally on your device with no telemetry or analytics.

### Does SecurePassManager connect to the internet?

By default, SecurePassManager does not connect to the internet. If you enable optional features like breach checking or cloud synchronization, limited internet connectivity will be used for those specific features only.

### Can I use SecurePassManager for sensitive or classified information?

SecurePassManager is designed with high security standards, but you should follow your organization's policies regarding software for sensitive information. For classified environments, ensure you:

1. Use the application on approved systems only
2. Verify the build with your security team
3. Consider the air-gapped deployment option
4. Follow all relevant security protocols

## Comparison Questions

### How does SecurePassManager compare to other password managers in terms of security?

SecurePassManager was designed with a security-first approach:

1. We prioritize security over convenience when trade-offs are necessary
2. We use modern, conservative cryptographic approaches rather than novel but less-tested methods
3. Our codebase is focused exclusively on password management, minimizing attack surface
4. We employ multiple layers of defense for critical security functions

### Is an open-source password manager more secure than a closed-source one?

Open-source software can have security advantages because:

1. The code can be reviewed by anyone, potentially identifying vulnerabilities faster
2. The cryptographic implementations can be verified by experts
3. There's transparency about how your data is handled

However, security ultimately depends on the quality of the code and the development practices rather than just whether it's open or closed source.

## Advanced Security Features

### Does SecurePassManager support hardware security keys?

SecurePassManager includes optional support for hardware security keys (like YubiKey) for additional security when built with the appropriate options.

### Can SecurePassManager be used with biometric authentication?

Yes, when built with biometric support options, SecurePassManager can integrate with:

1. Windows Hello
2. Touch ID on macOS/iOS
3. Android biometric authentication

Note that biometrics are used as a convenience feature and don't replace the master password entirely.

### Does SecurePassManager support two-factor authentication?

SecurePassManager supports optional two-factor authentication for unlocking the vault when built with proper support. This can include:

1. TOTP (Time-based One-Time Password) authentication
2. Hardware security keys
3. Biometric factors (when supported by your platform)

### How can I verify the authenticity of my SecurePassManager download?

Each release is digitally signed and includes cryptographic hashes that you can verify. Check the documentation for instructions on verification for your specific platform and build. 