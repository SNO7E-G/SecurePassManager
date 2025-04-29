# SecurePassManager

![SecurePassManager Logo](docs/assets/logo.png)

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.2.0-green.svg)](#)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey.svg)](#)

**SecurePassManager** is a high-security, open-source CLI password manager designed for users who prioritize security, privacy, and control. Built with modern C++17 and industry-standard cryptographic libraries, it offers advanced password management with zero reliance on cloud services.

## Key Features

🔒 **Military-Grade Encryption**
- AES-256-GCM encryption with authenticated ciphers
- Argon2id key derivation (winner of the Password Hashing Competition)
- ChaCha20-Poly1305 support for alternative encryption

🛡️ **Advanced Security Measures**
- Memory protection against cold boot attacks
- Anti-forensic techniques for sensitive data
- Configurable password policies and breach detection
- Optional hardware security module (HSM) integration

⚡ **Optimized Performance**
- Lightweight CLI interface with minimal dependencies
- Hardware acceleration where available (AES-NI)
- Fast database operations with SQLite

🔄 **Convenient Workflow**
- Strong password generator with various options
- Password strength analysis and improvement suggestions
- Secure import/export capabilities
- Optional secure cloud synchronization

## Installation

### Prerequisites
- CMake (3.15+)
- Modern C++ compiler supporting C++17
- OpenSSL (1.1.1+)
- SQLite3

### From Source

```bash
# Clone the repository
git clone https://github.com/SNO7E/SecurePassManager.git
cd SecurePassManager

# Run the automated setup script
./setup.bat  # Windows
./setup.sh   # Linux/macOS

# Or manually build:
mkdir build && cd build
cmake ..
cmake --build .
```

### Binary Packages

Pre-built binaries are available for major platforms in the [Releases](https://github.com/SNO7E/SecurePassManager/releases) section.

## Quick Start

### Creating a new password vault

```bash
securepass create --db my_passwords.db
```

### Adding a new password entry

```bash
securepass add --title "GitHub" --username "myusername" --url "github.com"
```

### Generating a strong password

```bash
securepass generate --length 20 --symbols --numbers
```

### Retrieving a password

```bash
securepass get --title "GitHub"
```

## Security Architecture

SecurePassManager implements a multi-layered security approach:

1. **Master Password**: The only key you need to remember, never stored anywhere
2. **Key Derivation**: Argon2id with configurable parameters (memory-hard to resist brute force)
3. **Encrypted Database**: All data stored in an encrypted SQLite database
4. **Secure Memory Handling**: Sensitive data is wiped from memory when no longer needed
5. **Enhanced Security Module**: Provides an additional security layer with breach detection

For more details on the security architecture, see [SECURITY.md](SECURITY.md).

## Building with Options

SecurePassManager can be built with various options:

```bash
# Enable GUI (requires Qt)
cmake -DENABLE_GUI=ON ..

# Enable Hardware Security Module support
cmake -DENABLE_HSM=ON ..

# Enable YubiKey support
cmake -DENABLE_YUBIKEY=ON ..

# Enable biometric authentication
cmake -DENABLE_BIOMETRICS=ON ..
```

## Documentation

Comprehensive documentation is available in the [docs](docs/) directory and covers:

- [User Guide](docs/user-guide.md)
- [Security Model](docs/security-model.md)
- [Development Guide](docs/development-guide.md)
- [API Reference](docs/api-reference.md)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

SecurePassManager leverages several excellent open-source libraries:

- [OpenSSL](https://www.openssl.org/)
- [SQLite](https://www.sqlite.org/)
- [Argon2](https://github.com/P-H-C/phc-winner-argon2)

## Contact

- Project maintained by [Mahmoud Ashraf (SNO7E)](https://github.com/SNO7E)
- Report bugs and issues on the [Issue Tracker](https://github.com/SNO7E/SecurePassManager/issues) 