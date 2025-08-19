# HanCover - Coverage Reports for PRs

![GitHub CI](https://github.com/farhan-ahmed1/hancover-action/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-85%25-green)

> A GitHub Action that processes LCOV and Cobertura coverage files, calculates total and diff coverage for PRs, and posts organized coverage reports as sticky comments with configurable thresholds.

## Features

- **Multi-format support**: LCOV and Cobertura XML
- **Diff coverage**: Track coverage on changed lines only
- **Smart grouping**: Auto-group by package or define custom groups
- **Threshold checking**: Fail builds when coverage drops
- **Sticky PR comments**: Updates existing comments instead of spamming
- **Size limits**: Configurable file size limits for security
- **Fast**: Efficient parsing and computation

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

## Features

- **Multi-format support**: LCOV, Cobertura (Clover & JaCoCo coming soon)
- **Diff coverage**: Focus on changed lines in PRs
- **Smart grouping**: Auto-detect packages or define custom groups
- **Sticky comments**: Update existing PR comments instead of spam
- **Security-first**: Size limits, safe XML parsing, minimal permissions
- **Fast**: Streaming parsers for large coverage files

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

## License

Apache-2.0 - see [LICENSE](LICENSE) for details.
