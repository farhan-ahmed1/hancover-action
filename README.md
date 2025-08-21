# HanCover Action

![GitHub CI](https://github.com/farhan-ahmed1/hancover-action/actions/workflows/ci.yml/badge.svg)
![CodeQL](https://github.com/farhan-ahmed1/hancover-action/actions/workflows/codeql.yml/badge.svg)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/farhan-ahmed1/96e4dc85e2b5c6a2e7f7cdcdc576eb6c/raw/coverage-badge.json)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/farhan-ahmed1/hancover-action/badge)](https://scorecard.dev/viewer/?uri=github.com/farhan-ahmed1/hancover-action)

A GitHub Action that generates coverage reports for Pull Requests with change detection, dynamic badges, and support for multiple coverage formats.

## Features

- **Multi-format support**: Automatically detects and parses LCOV, Cobertura, JaCoCo, and Clover coverage files
- **Change tracking**: Compares PR coverage against main branch with visual delta indicators
- **Smart PR comments**: Single sticky comment that updates with each push
- **Dynamic badges**: Auto-updating coverage and change badges via GitHub Gists
- **Package organization**: Intelligent grouping with customizable package structure
- **Security focused**: Minimal permissions, input validation, and secure XML processing

## Quick Setup

### Basic PR Coverage

Add coverage reports to Pull Requests with this minimal setup:

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
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      
      - run: npm ci
      - run: npm test -- --coverage
      
      - name: Coverage Report
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info
          min-threshold: 80
```

This creates PR comments with coverage tables and health indicators.

### Enhanced Setup with Change Detection

For coverage badges and change tracking, additional setup is required using GitHub Gists.

**Step 1: Create a GitHub Gist**
1. Go to [gist.github.com](https://gist.github.com)
2. Create a **public** gist with filename `coverage.json` and content: `{"coverage": 0}`
3. Note the Gist ID from the URL

**Step 2: Add Repository Secrets**
1. Go to repository Settings → Secrets and variables → Actions
2. Add `COVERAGE_GIST_ID` with your gist ID
3. Add `GIST_TOKEN` with a [personal access token](https://github.com/settings/tokens) having `gist` scope

**Step 3: Update Workflow**
```yaml
- name: Coverage Report with Change Detection
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    gist-id: ${{ secrets.COVERAGE_GIST_ID }}
    github-token: ${{ secrets.GIST_TOKEN }}
    min-threshold: 80
```

**Step 4: Add Main Branch Workflow**
Create `.github/workflows/coverage-main.yml`:

```yaml
name: Update Coverage Baseline
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  update-baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      
      - run: npm ci
      - run: npm test -- --coverage
      
      - name: Update Coverage Baseline
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info
          gist-id: ${{ secrets.COVERAGE_GIST_ID }}
          github-token: ${{ secrets.GIST_TOKEN }}
```

**Step 5: Add Dynamic README Badge**
Add this badge to your README for auto-updating coverage display:

```markdown
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/USERNAME/GIST_ID/raw/coverage-badge.json)
```

Replace `USERNAME` with your GitHub username and `GIST_ID` with your gist ID.

## What You Get

### Basic PR Comments
Clean, organized coverage reports in Pull Request comments:

```
Coverage Report

Overall Coverage: 87.1% | Lines Covered: 1523/1749

Package Coverage:
┌─────────────┬───────────────┬──────────────┬───────────────┬────────┐
│ Package     │ Statements    │ Branches     │ Functions     │ Health │
├─────────────┼───────────────┼──────────────┼───────────────┼────────┤
│ src/core    │ 95.2% (120/126) │ 88.9% (24/27) │ 100.0% (8/8) │   ✅   │
│ src/utils   │ 78.3% (47/60)   │ 66.7% (4/6)  │ 85.7% (6/7)  │   ✅   │
│ **Summary** │ **87.1% (167/192)** │ **84.8% (28/33)** │ **93.3% (14/15)** │ **✅** │
└─────────────┴───────────────┴──────────────┴───────────────┴────────┘

Changes Coverage: 91.3% (42/46 lines)
```

### Enhanced with Change Detection

<!-- TODO: Add screenshot of enhanced PR comment with badges -->
*[Screenshot placeholder: Enhanced PR comment with coverage badges and change indicators]*

With change detection enabled:
- Coverage and change badges at the top of PR comments
- Delta indicators showing coverage changes vs main branch  
- Collapsible detailed coverage tables
- Auto-updating README badges

<!-- TODO: Add screenshot of dynamic README badge -->
*[Screenshot placeholder: Dynamic README badge that updates automatically]*

## Supported Coverage Formats

| Format | File Extensions | Common Tools |
|--------|----------------|--------------|
| **LCOV** | `.info` | Jest, Vitest, Karma, c8, nyc |
| **Cobertura** | `.xml` | .NET, Python (coverage.py), Maven |
| **JaCoCo** | `.xml` | Java, Kotlin, Scala |
| **Clover** | `.xml` | PHP (PHPUnit), JavaScript |

The action automatically detects the format based on file content and structure.

## Documentation

### Setup & Configuration
- **[Setup Guide](./docs/SETUP-GUIDE.md)** - Complete setup instructions including file-based alternatives
- **[Configuration Guide](./docs/CONFIGURATION.md)** - Advanced package grouping and report customization
- **[API Reference](./docs/API-REFERENCE.md)** - Complete input/output reference and configuration options

### Examples
- **[Basic PR Coverage](./examples/basic-pr-coverage.yml)** - Simple coverage comments
- **[Enhanced with Badges](./examples/enhanced-with-badges.yml)** - Full setup with change detection
- **[Multi-format Support](./examples/multi-format.yml)** - Different coverage formats
- **[Monorepo Setup](./examples/monorepo-setup.yml)** - Complex project configuration

### Reference
- **[Token Flow Guide](./docs/TOKEN-FLOW.md)** - GitHub tokens and authentication
- **[Security Policy](./SECURITY.md)** - Security best practices and reporting
- **[Contributing Guide](./CONTRIBUTING.md)** - Contributing to the project

## Language Examples

### JavaScript/TypeScript (Jest, Vitest)
```yaml
- run: npm test -- --coverage
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
```

### .NET Projects
```yaml
- run: dotnet test --collect:"XPlat Code Coverage" --results-directory coverage
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/**/coverage.cobertura.xml
```

### Java Projects (Maven)
```yaml
- run: mvn test jacoco:report
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: target/site/jacoco/jacoco.xml
```

### Python Projects
```yaml
- run: |
    pip install coverage
    coverage run -m pytest
    coverage xml
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage.xml
```

See [examples/](./examples/) for complete workflow files and advanced configurations.

## Security

HanCover Action follows security best practices:

- **Minimal permissions**: Only requires `pull-requests: write` and `contents: read`
- **Input validation**: All inputs are validated and sanitized
- **Size limits**: Built-in protections against large file attacks (50MB per file, 200MB total)
- **Secure parsing**: XXE protection and safe XML processing

### Best Practices

```yaml
# Pin to specific versions
uses: farhan-ahmed1/hancover-action@v1.0.0  # ✅ Recommended
uses: farhan-ahmed1/hancover-action@main    # ❌ Avoid

# Use minimal permissions
permissions:
  pull-requests: write  # For PR comments
  contents: read       # For repository access

# Secure token management
github-token: ${{ secrets.GIST_TOKEN }}     # ✅ Use secrets
github-token: "ghp_your_token_here"         # ❌ Never hardcode
```

Report security issues via [SECURITY.md](SECURITY.md).

## Troubleshooting

### Common Issues

**No coverage files found**
- Verify coverage files are generated before running the action
- Check file paths match the `files` input pattern
- Ensure test command runs with coverage enabled

**Failed to update gist**
- Verify `GIST_TOKEN` has `gist` scope permissions
- Ensure the gist exists and is public
- Check the gist ID is correct

**Action fails on coverage threshold**
- Review coverage requirements in `min-threshold`
- Use `warn-only: true` to prevent workflow failure
- See [API Reference](./docs/API-REFERENCE.md) for threshold configuration

For additional help, see [Setup Guide troubleshooting](./docs/SETUP-GUIDE.md) or [open an issue](https://github.com/farhan-ahmed1/hancover-action/issues).

## License

Apache-2.0 - see [LICENSE](LICENSE) for details.
