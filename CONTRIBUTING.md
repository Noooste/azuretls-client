# Contributing to AzureTLS Client

First off, thank you for considering contributing to this project! This document provides guidelines and instructions to help you contribute effectively.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

Before submitting a bug report:
- Check the issue tracker to see if the bug has already been reported
- Ensure the bug is related to the Go HTTP client and not a dependency

When submitting a bug report:
- Use a clear and descriptive title
- Describe the exact steps to reproduce the bug
- Provide specific examples (code snippets, configuration files)
- Include relevant logs and error messages
- Describe the expected behavior
- Mention your environment details (Go version, OS, etc.)

### Suggesting Enhancements

When suggesting an enhancement:
- Use a clear and descriptive title
- Provide a step-by-step description of the suggested enhancement
- Explain why this enhancement would be useful to most users
- Include code examples if applicable

### Pull Requests

Follow these steps to submit a pull request:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Run tests to ensure your changes don't break existing functionality
5. Commit your changes with clear commit messages that follow our commit message conventions
6. Push to the branch (`git push origin feature/your-feature-name`)
7. Open a pull request

#### Pull Request Guidelines

- Follow the standard Go code style and formatting guidelines
- Write comprehensive comments for public functions, types, and methods
- Include tests for new features or bug fixes
- Update documentation to reflect any changes
- Ensure all tests pass before submitting
- Make sure your code lints without errors
- Keep each PR focused on a single change to make review easier

## Development Setup

1. Install Go (version 1.24+)
2. Clone the repository
3. Install dependencies: `go mod download`
4. Run tests: `go test ./...`

## Coding Standards

### Go Code Style

- Follow the [Effective Go](https://golang.org/doc/effective_go) guidelines
- Use `gofmt` to format your code
- Follow standard Go naming conventions
- Document all exported functions, types, and methods

### Commit Message Conventions

Structure your commit messages as follows:

```
<type>: <subject>

<body>

<footer>
```

Types:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Changes that do not affect code meaning (formatting, etc.)
- `refactor`: Code changes that neither fix a bug nor add a feature
- `perf`: Code changes that improve performance
- `test`: Adding or modifying tests
- `chore`: Changes to build process or auxiliary tools

Example:
```
feat: add support for HTTP/2 trailers

Implement support for reading and setting HTTP/2 trailers in responses.
This enhances the client's compliance with RFC 7540.

Closes #123
```

## Testing

- Write unit tests for new features and bug fixes
- Aim for high test coverage, especially for critical components
- Include integration tests where appropriate
- Ensure your tests are fast and reliable

## Documentation

- Update the README.md with details of changes to the interface
- Add comments to your code, especially for complex logic
- Use godoc-compatible comments for exported functions and types

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project.

## Questions or Need Help?

Feel free to open an issue with the "question" label if you need help or have questions about contributing.

Thank you for contributing to our project!
