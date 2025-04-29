# Contributing to Secure Password Manager

Thank you for your interest in contributing to the Secure Password Manager project! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating in this project.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** to your local machine
3. **Set up the development environment** by following the instructions in the README.md

## Development Process

### Branching Strategy

We use a simplified Git flow:

- `main` - The primary branch containing stable releases
- `develop` - The development branch with the latest features
- Feature branches - Used for developing new features or fixing bugs

### Creating a New Feature or Bug Fix

1. Create a new branch from `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/your-feature-name
   # or for bug fixes
   git checkout -b fix/issue-description
   ```

2. Make your changes and commit them:
   ```bash
   git commit -m "feat: description of your changes"
   ```
   
   We follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

3. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Create a Pull Request to the `develop` branch of the main repository

### Coding Standards

- Follow C++17 standards
- Use consistent indentation (4 spaces)
- Add comments for complex logic
- Include documentation for public APIs
- Write unit tests for new functionality

### Security Considerations

- Never commit sensitive information (keys, passwords, personal data)
- All encryption operations must use secure algorithms
- Memory containing sensitive data must be securely wiped
- Input validation is mandatory for all user inputs
- Follow the principle of least privilege

## Pull Request Process

1. Update documentation to reflect any changes
2. Add tests for new features
3. Ensure the CI build passes
4. Update the changelog with your changes
5. Get a review from at least one maintainer
6. Squash your commits if requested

## Testing

- All code should have appropriate unit tests
- Tests should cover both success and failure cases
- Aim for high code coverage, especially for security-critical code

## Documentation

When adding new features, please update the relevant documentation:

- Update API documentation within the code
- Update the README.md if needed
- Consider adding examples for complex features

## Reporting Issues

When reporting issues, please include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Screenshots if applicable
- Environment details (OS, compiler version, etc.)

## Feature Requests

Feature requests are welcome! Please provide:

- A clear description of the feature
- Justification for the feature (use cases)
- Any implementation ideas you have

## Contact

If you have questions about contributing that aren't answered here, please contact the maintainer:

- Mahmoud Ashraf (SNO7E)
- GitHub: [@SNO7E](https://github.com/SNO7E-G)

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](../LICENSE). 