# Contributing to SecurePassManager

Thank you for your interest in contributing to SecurePassManager! This document provides guidelines and instructions for contributing to make the process smooth for everyone.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report. Following these guidelines helps maintainers understand your report, reproduce the behavior, and find related reports.

- **Use the GitHub issue tracker** — Check if the bug has already been reported by searching on GitHub under [Issues](https://github.com/SNO7E/SecurePassManager/issues).
- **Use the bug report template** — If you're reporting a bug, make sure to use the bug report template provided.
- **Provide detailed information** — Include as many details as possible: which version you're using, what environment (OS, compiler, etc.), and steps to reproduce.
- **Include logs and screenshots** — If applicable, include log outputs and screenshots to help explain your problem.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion, including completely new features and minor improvements to existing functionality.

- **Use the GitHub issue tracker** — Check if the enhancement has already been suggested by searching on GitHub under [Issues](https://github.com/SNO7E/SecurePassManager/issues).
- **Use the feature request template** — If you're suggesting a feature, make sure to use the feature request template provided.
- **Provide context** — Explain why this enhancement would be useful to most SecurePassManager users.
- **Consider the scope** — Keep in mind that the focus of SecurePassManager is security and privacy.

### Pull Requests

- **Follow the coding style** — Make sure your code follows the style guidelines of this project.
- **Document new code** — Document new code based on the documentation style of the project.
- **Add tests for new features** — Add tests that cover your new functionality.
- **Update documentation** — Update the documentation to reflect any changes.
- **Create feature branches** — Don't ask us to pull from your master branch.
- **One pull request per feature** — If you want to do more than one thing, send multiple pull requests.
- **Send coherent history** — Make sure each individual commit in your pull request is meaningful.

## Style Guides

### Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line
- Consider starting the commit message with an applicable emoji:
  - 🔒 `:lock:` when improving security
  - ✨ `:sparkles:` when adding a new feature
  - 🐛 `:bug:` when fixing a bug
  - 📝 `:memo:` when adding or updating documentation
  - 🚀 `:rocket:` when improving performance
  - 🧪 `:test_tube:` when adding tests
  - 🔄 `:arrows_counterclockwise:` when refactoring code
  - 🔧 `:wrench:` when updating configuration files

### C++ Style Guide

We follow the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with a few modifications:

1. Use 4 spaces for indentation
2. Use snake_case for variable names and function names
3. Use CamelCase for class and struct names
4. Use ALL_CAPS for constants and macros

### Documentation Style Guide

- Use [Doxygen](https://www.doxygen.nl/manual/docblocks.html) for code documentation
- Document all public methods and classes
- Keep documentation up-to-date with code changes

## Development Environment Setup

### Prerequisites

- CMake (3.15+)
- Modern C++ compiler supporting C++17
- OpenSSL (1.1.1+)
- SQLite3

### Setup Steps

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/SecurePassManager.git`
3. Add upstream remote: `git remote add upstream https://github.com/SNO7E/SecurePassManager.git`
4. Create a new branch for your feature: `git checkout -b feature/amazing-feature`

### Building for Development

```bash
mkdir build && cd build
cmake .. -DBUILD_TESTING=ON
cmake --build .
```

### Running Tests

```bash
cd build
ctest -V
```

## Security Policy

Security is our top priority. If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md) for responsible disclosure.

## Release Process

1. Features are developed in feature branches
2. Pull requests are reviewed and merged to develop
3. Releases are created from develop to main
4. Tags are created for each release with semantic versioning

## Questions?

If you have any questions about contributing, please open an issue or contact the maintainers directly.

Thank you for contributing to SecurePassManager! 