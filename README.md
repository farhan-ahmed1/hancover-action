# HanCover Action

![GitHub CI](https://github.com/farhan-ahmed1/hancover-action/actions/workflows/ci.yml/badge.svg)
![CodeQL](https://github.com/farhan-ahmed1/hancover-action/actions/workflows/codeql.yml/badge.svg)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/farhan-ahmed1/96e4dc85e2b5c6a2e7f7cdcdc576eb6c/raw/coverage-badge.json)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/farhan-ahmed1/hancover-action/badge)](https://scorecard.dev/viewer/?uri=github.com/farhan-ahmed1/hancover-action)

A GitHub Action that generates comprehensive coverage reports for Pull Requests with change detection, dynamic badges, and support for multiple coverage formats.

## Features

- **Multi-format support**: LCOV, Cobertura, JaCoCo, and Clover (auto-detected)
- **Change tracking**: Compare PR coverage against main branch with delta indicators
- **Smart PR comments**: Single comment that updates with each push
- **Dynamic badges**: Auto-updating coverage badges via GitHub Gists
- **Package organization**: Intelligent grouping with customizable structure
- **Security focused**: Minimal permissions, input validation, secure XML processing

## Quick Start

### Basic Coverage Reports

```yaml
name: PR Coverage
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  pull-requests: write
  contents: read

jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4  # Adjust for your language
        with:
          node-version: '20'
          cache: 'npm'
      
      - run: npm ci
      - run: npm test -- --coverage
      
      - name: Coverage Report
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info  # Adjust for your coverage format
          min-threshold: 80
```

### Enhanced with Change Detection & Badges

For change tracking and dynamic badges, see the **[Enhanced Setup Guide](./examples/workflows.yml#enhanced-with-badges-and-change-detection)**.

## Supported Languages & Formats

| Language | Format | Typical File Path |
|----------|--------|-------------------|
| JavaScript/TypeScript | LCOV | `coverage/lcov.info` |
| .NET | Cobertura | `coverage/**/coverage.cobertura.xml` |
| Java | JaCoCo | `target/site/jacoco/jacoco.xml` |
| Python | Cobertura | `coverage.xml` |
| PHP | Clover | `coverage.xml` |

The action automatically detects the format. See **[Compatibility Reference](./docs/COMPATIBILITY.md)** for detailed setup instructions.

## Example Output

### Basic PR Comment
```text
Coverage Report

Overall Coverage: 87.1% | Lines Covered: 1523/1749

Package Coverage:
┌─────────────┬───────────────┬──────────────┬───────────────┬────────┐
│ Package     │ Statements    │ Branches     │ Functions     │ Health │
├─────────────┼───────────────┼──────────────┼───────────────┼────────┤
│ src/core    │ 95.2% (120/126) │ 88.9% (24/27) │ 100.0% (8/8) │   ✅   │
│ src/utils   │ 78.3% (47/60)   │ 66.7% (4/6)  │ 85.7% (6/7)  │   ✅   │
└─────────────┴───────────────┴──────────────┴───────────────┴────────┘

Changes Coverage: 91.3% (42/46 lines)
```

### Enhanced with Badges
When change detection is enabled, you get coverage badges, delta comparisons, and auto-updating README badges.

<img width="828" alt="Enhanced coverage report with badges and change detection" src="https://github.com/user-attachments/assets/98c1bc36-a9df-4c86-8f89-35e384301c9e" />

## Documentation

- **[Complete Workflow Examples](./examples/workflows.yml)** - All setup patterns and language examples
- **[API Reference](./docs/API-REFERENCE.md)** - Input/output reference and configuration options
- **[Configuration Guide](./docs/CONFIGURATION.md)** - Advanced package grouping for monorepos
- **[Compatibility Reference](./docs/COMPATIBILITY.md)** - Supported languages and formats
- **[Troubleshooting Guide](./docs/TROUBLESHOOTING.md)** - Common issues and solutions

## Need Help?

- **Common issues**: Check the [Troubleshooting Guide](./docs/TROUBLESHOOTING.md)
- **Setup examples**: See [Complete Workflow Examples](./examples/workflows.yml)
- **Bug reports**: Open an [issue](https://github.com/farhan-ahmed1/hancover-action/issues)

## License

MIT License - see [LICENSE](LICENSE) for details.
