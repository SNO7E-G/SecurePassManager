# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2023-06-15

### Added
- Enhanced Security module for improved password protection
- Password breach detection against common password databases
- Password strength evaluation with detailed suggestions
- Secure file encryption/decryption capabilities
- Memory protection against cold boot attacks
- Configurable password policies

### Changed
- Upgraded to Argon2id for key derivation (when available)
- Improved secure memory handling
- Better error messages and user feedback
- Updated OpenSSL dependencies to latest version

### Fixed
- Memory leak in database connection handling
- Improper error handling in password generation
- Timing attack vulnerability in password comparison
- Command line parsing issues with special characters

## [1.1.0] - 2023-03-10

### Added
- Password generation with configurable options
- Import/export capabilities
- Password history tracking
- Security audit functionality
- Basic password breach detection

### Changed
- Improved database schema for better performance
- Enhanced command-line interface
- Better error handling and reporting
- Updated cryptographic implementation

### Fixed
- Database corruption issue when power loss occurs during write
- Memory leak in encryption routine
- Command-line parsing bug with quotes
- Password entry display formatting issues

## [1.0.0] - 2023-01-05

### Added
- Initial release
- Basic password storage and retrieval
- AES-256-GCM encryption
- Master password protection
- CLI interface for all operations
- SQLite encrypted database
- Basic password generation 