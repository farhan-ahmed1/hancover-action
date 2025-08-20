# HanCover - Coverage Reports for PRs

![GitHub CI](https://github.com/farhan-ahmed1/hancover-action/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/farhan-ahmed1/96e4dc85e2b5c6a2e7f7cdcdc576eb6c/raw/hancover-coverage.json)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/farhan-ahmed1/hancover-action/badge)](https://scorecard.dev/viewer/?uri=github.com/farhan-ahmed1/hancover-action)

A GitHub Action that generates comprehensive coverage reports with change detection for Pull Requests. Supports multiple coverage formats and provides dynamic badges showing coverage changes compared to the main branch.

## Features

- **Multiple format support**: LCOV, Cobertura, JaCoCo, and Clover coverage files
- **Change detection**: Automatic baseline comparison using GitHub Gists
- **Dynamic badges**: Coverage and change badges that update automatically
- **Smart analysis**: Package grouping, diff coverage, and delta calculations  
- **Sticky comments**: Clean PR comments that update instead of spam
- **Threshold checking**: Configurable coverage requirements
- **Secure**: Minimal permissions, input validation, and safe parsing

## Quick Start

### Basic Usage

```yaml
name: Coverage
on:
  pull_request:

permissions:
  pull-requests: write
  contents: read

jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      
      - run: npm ci
      - run: npm test -- --coverage
      
      - name: Coverage Report
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info
          min-threshold: 80
```

### With Change Detection (Recommended)

Enable change badges by setting up a GitHub Gist for baseline storage:

```yaml
Enable change badges by setting up a GitHub Gist for baseline storage:

```yaml
- name: Coverage Report with Changes
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    gist-id: ${{ secrets.COVERAGE_GIST_ID }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
    min-threshold: 80
```

**Setup Guide**: [Complete Gist Setup Instructions](./docs/COMPLETE-SETUP.md)

## Example Output
```

**📋 Setup Guide**: [Complete Gist Setup Instructions](./docs/COMPLETE-SETUP.md)
## 📊 Example Output

With the Gist setup, your PR comments will include both badges:

![Coverage](https://img.shields.io/badge/coverage-87.1%25-green) ![Changes](https://img.shields.io/badge/changes-+1.9%25-brightgreen)

**Overall Coverage:** 87.1% | **Lines Covered:** 1523/1749  

_Changes made in this PR increased coverage by 1.9 percentage points._

<details>
<summary><b>Detailed Coverage by Package</b></summary>

| Package | Statements | Branches | Functions | Health |
|---------|------------|----------|-----------|--------|
| src/core | 95.2% (120/126) | 88.9% (24/27) | 100.0% (8/8) | ✅ |
| src/utils | 78.3% (47/60) | 66.7% (4/6) | 85.7% (6/7) | ✅ |
| **Summary** | **87.1% (167/192)** | **84.8% (28/33)** | **93.3% (14/15)** | **✅** |

</details>

## Configuration

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `files` | Coverage file patterns (e.g., `'coverage/lcov.info'`) | Yes | - |
| `gist-id` | GitHub Gist ID for baseline storage (enables change badges) | No | - |
| `github-token` | GitHub token for API access | No | `GITHUB_TOKEN` |
| `min-threshold` | Minimum coverage threshold for health indicators | No | `50` |
| `comment-mode` | `'update'` (sticky) or `'new'` | No | `'update'` |
| `warn-only` | Don't fail on threshold violations | No | `false` |
| `baseline-files` | Baseline coverage files (alternative to gist) | No | - |
| `groups` | YAML configuration for custom package grouping | No | - |

## Outputs

| Output | Description |
|--------|-------------|
| `coverage-pct` | Overall project coverage percentage |
| `changes-coverage-pct` | Coverage percentage for code changes in this PR |
| `coverage-delta` | Coverage change compared to main branch (when gist-id provided) |

## Coverage Formats Supported

- **LCOV** (`.info` files) - Jest, Vitest, Karma, etc.
- **Cobertura** (`.xml` files) - .NET, Python, etc.  
- **JaCoCo** (`.xml` files) - Java, Kotlin, Scala
- **Clover** (`.xml` files) - PHP, JavaScript

## Documentation

- **[Complete Setup Guide](./docs/COMPLETE-SETUP.md)** - Step-by-step Gist setup for change badges
- **[Token Flow Guide](./docs/TOKEN-FLOW.md)** - How authentication and data flow works
- **[Coverage Badge Setup](./docs/COVERAGE-BADGE.md)** - Legacy badge setup documentation

## Security

HanCover is designed with security as a top priority:

- **Minimal permissions**: Only requires `pull-requests: write` and `contents: read`
- **Safe parsing**: XXE protection, input validation, and secure XML processing
- **Size limits**: Built-in protections against large file attacks
- **Supply chain security**: Signed releases, dependency scanning, and regular audits

**Security best practices:**
```yaml
# Pin to specific versions
uses: farhan-ahmed1/hancover-action@v1.0.0

# Avoid using branches or tags
uses: farhan-ahmed1/hancover-action@main
```

Report security issues: See [SECURITY.md](SECURITY.md)

## License

Apache-2.0 - see [LICENSE](LICENSE) for details.
