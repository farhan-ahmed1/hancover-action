# Contributing to HanCover Action

Thank you for your interest in contributing! We welcome contributions of all kinds.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/hancover-action.git`
3. Install dependencies: `npm install`
4. Make your changes
5. Run tests: `npm test`
6. Build: `npm run build`
7. Submit a pull request

## Development Setup

### Prerequisites

- Node.js 20+
- npm or pnpm

### Local Development

```bash
# Install dependencies
npm install

# Run tests in watch mode
npm run test -- --watch

# Lint code
npm run lint

# Build TypeScript
npm run build
```

## Code Style

- We use TypeScript with strict mode enabled
- ESLint for code linting
- Prefer functional programming patterns
- Add tests for new features

## Testing

- Use Vitest for testing
- Add test fixtures in `test/fixtures/`
- Test both happy paths and error cases
- Aim for good coverage of new code

## Pull Request Guidelines

1. **Keep PRs focused**: One feature/fix per PR
2. **Write good commit messages**: Use conventional commits format
3. **Add tests**: Include tests for new functionality
4. **Update docs**: Update README.md if needed
5. **Check CI**: Ensure all checks pass

## Reporting Issues

When reporting issues, please include:

- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Sample coverage files (if relevant)
- Environment details (OS, Node version, etc.)

## Code of Conduct

Please note that this project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to abide by its terms.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
