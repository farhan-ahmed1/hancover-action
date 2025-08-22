# HanCover Action v0.1.0 🎉

First official release of HanCover Action - a GitHub Action that generates comprehensive coverage reports for Pull Requests with intelligent change detection and dynamic badges.

## What's New

### Core Features
- **Multi-format support**: Automatically detects and parses LCOV, Cobertura, JaCoCo, and Clover coverage files
- **Smart PR comments**: Single sticky comment that updates with each push (no spam!)
- **Change tracking**: Compares PR coverage against main branch with visual delta indicators
- **Dynamic badges**: Auto-updating coverage and change badges via GitHub Gists
- **Package organization**: Intelligent grouping with customizable package structure

### Security & Performance
- **Security-focused**: XXE protection, input validation, and secure XML processing
- **File size limits**: Built-in protection (50MB per file, 200MB total)
- **Timeout protection**: Configurable execution timeout (default 120s)
- **Streaming parser**: Handles large coverage files efficiently

### Developer Experience
- **Easy setup**: 5-minute basic setup, 15-minute enhanced setup
- **Comprehensive docs**: Setup guides, examples, and API reference
- **Smart defaults**: Ecosystem-aware configuration for Node.js, Python, Java, etc.

## Quick Start

### Basic PR Coverage
```yaml
- name: Coverage Report
  uses: farhan-ahmed1/hancover-action@v0.1.0
  with:
    files: coverage/lcov.info
    min-threshold: 80
```

### Enhanced with Change Detection
```yaml
- name: Coverage Report with Change Detection
  uses: farhan-ahmed1/hancover-action@v0.1.0
  with:
    files: coverage/lcov.info
    gist-id: ${{ secrets.COVERAGE_GIST_ID }}
    github-token: ${{ secrets.GIST_TOKEN }}
    min-threshold: 80
```

## Supported Formats

| Format | File Extensions | Common Tools |
|--------|----------------|--------------|
| **LCOV** | `.info` | Jest, Vitest, Karma, c8, nyc |
| **Cobertura** | `.xml` | .NET, Python (coverage.py), Maven |
| **JaCoCo** | `.xml` | Java, Kotlin, Scala |
| **Clover** | `.xml` | PHP (PHPUnit), JavaScript |

## Documentation

- [Setup Guide](https://github.com/farhan-ahmed1/hancover-action/blob/main/docs/SETUP-GUIDE.md)
- [Configuration Guide](https://github.com/farhan-ahmed1/hancover-action/blob/main/docs/CONFIGURATION.md)
- [API Reference](https://github.com/farhan-ahmed1/hancover-action/blob/main/docs/API-REFERENCE.md)
- [Examples](https://github.com/farhan-ahmed1/hancover-action/tree/main/examples)

## Security

HanCover Action follows security best practices:
- Minimal permissions required (`pull-requests: write`, `contents: read`)
- Input validation and sanitization
- XXE protection and safe XML processing
- File size limits and timeout protection

## Contributing

We welcome contributions! Please see our [Contributing Guide](https://github.com/farhan-ahmed1/hancover-action/blob/main/CONTRIBUTING.md) for details.

## License

Apache-2.0 - see [LICENSE](https://github.com/farhan-ahmed1/hancover-action/blob/main/LICENSE) for details.

---

**Full Changelog**: https://github.com/farhan-ahmed1/hancover-action/blob/main/CHANGELOG.md
