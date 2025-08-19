# HanCover - Coverage Reports for PRs

![GitHub CI](https://github.com/farhan-ahmed1/hancover-action/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/farhan-ahmed1/28d3a47ac254c0d740450d8a29fd3613/raw/hancover-coverage.json)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/farhan-ahmed1/hancover-action/badge)](https://scorecard.dev/viewer/?uri=github.com/farhan-ahmed1/hancover-action)

A GitHub Action that processes LCOV and Cobertura coverage files, calculates total and diff coverage for PRs, and posts organized coverage reports as sticky comments with configurable thresholds.

## Features

- **Multi-format support**: LCOV and Cobertura XML
- **Enhanced coverage system**: Smart package grouping, code changes analysis, and delta comparison
- **Changes badge**: Visual delta showing coverage improvement/decline vs main branch using local JSON file
- **Diff coverage**: Track coverage on changed lines only
- **Smart grouping**: Auto-group by package or define custom groups
- **Threshold checking**: Fail builds when coverage drops
- **Sticky PR comments**: Updates existing comments instead of spamming
- **Size limits**: Configurable file size limits for security
- **Fast**: Efficient parsing and computation

## Enhanced Coverage System

The new enhanced coverage system provides comprehensive coverage analysis with:

- **Smart Package Grouping**: Automatically organizes files by directory structure
- **Code Changes Coverage**: Shows coverage only for lines modified in the PR
- **Changes Badge**: Visual delta badge showing coverage improvement/decline vs main branch stored in local JSON
- **Delta Analysis**: Compares PR coverage against main branch baseline
- **Collapsible Tables**: Clean, organized presentation with badges
- **Health Indicators**: Visual status based on configurable thresholds

[📖 Read the Enhanced Coverage Guide](./docs/ENHANCED-COVERAGE.md)
[🏷️ Coverage Badge Setup](./docs/COVERAGE-BADGE.md)

> **Note**: For coverage badges on your main branch, you'll need to add a separate workflow to your repository. See the [Coverage Badge Setup Guide](./docs/COVERAGE-BADGE.md) for complete instructions.
> 
> *This repository uses the same approach - our coverage badge is maintained by the [Coverage Badge workflow](.github/workflows/coverage-badge.yml) and manually updated.*

## Quick Start

```yaml
name: coverage
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  pull-requests: write
  contents: read

jobs:
  hancover:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }

      - uses: actions/setup-node@v4
        with: { node-version: '20' }

      - run: npm ci
      - run: npm test -- --coverage   # produces coverage/lcov.info

      - name: HanCover
        uses: farhan-ahmed1/hancover-action@v0
        with:
          files: |
            coverage/**/lcov.info
            **/cobertura.xml
          thresholds: |
            total:80
            diff:75
          comment-mode: update
          warn-only: false
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `files` | Glob patterns for coverage files | Yes | - |
| `base-ref` | Base commit SHA (defaults to PR base) | No | - |
| `thresholds` | Coverage thresholds (e.g., `total:80\ndiff:75`) | No | - |
| `warn-only` | Don't fail on threshold breach | No | `false` |
| `comment-mode` | `update` (sticky) or `new` | No | `update` |
| `groups` | YAML groups definition | No | - |
| `max-bytes-per-file` | Max file size in bytes | No | `52428800` (50MB) |
| `max-total-bytes` | Max total size in bytes | No | `209715200` (200MB) |
| `timeout-seconds` | Execution timeout | No | `120` |
| `strict` | Fail on oversize/invalid files | No | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `total_coverage` | Total line coverage percentage |
| `diff_coverage` | Diff (changed lines) coverage percentage |
| `branch_coverage` | Branch coverage percentage (if available) |
| `coverage-pct` | Project coverage percentage |
| `changes-coverage-pct` | Code changes coverage percentage |
| `coverage-delta` | Coverage delta compared to main branch |

## Security

HanCover is designed with security as a top priority:

- **Minimal permissions**: Only requires `pull-requests: write` and `contents: read`
- **Safe XML parsing**: XXE protection, no external entities, input validation
- **File size limits**: Configurable limits (50MB/file, 200MB total) prevent resource exhaustion
- **Supply chain security**: Signed releases, regular audits, dependency scanning

Always pin to specific versions for security:
```yaml
uses: farhan-ahmed1/hancover-action@v0.1.0  # ✅ Good
uses: farhan-ahmed1/hancover-action@main     # ❌ Avoid
```

Report security issues via [SECURITY.md](SECURITY.md).

## License

Apache-2.0 - see [LICENSE](LICENSE) for details.
