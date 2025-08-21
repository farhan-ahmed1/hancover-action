# HanCover Action

![GitHub CI](https://github.com/farhan-ahmed1/hancover-action/actions/workflows/ci.yml/badge.svg)
![CodeQL](https://github.com/farhan-ahmed1/hancover-action/actions/workflows/codeql.yml/badge.svg)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/farhan-ahmed1/96e4dc85e2b5c6a2e7f7cdcdc576eb6c/raw/coverage-badge.json)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/farhan-ahmed1/hancover-action/badge)](https://scorecard.dev/viewer/?uri=github.com/farhan-ahmed1/hancover-action)

A GitHub Action that generates comprehensive coverage reports for Pull Requests with intelligent change detection, dynamic badges, and support for multiple coverage formats.

## Key Features

- **Multi-format support**: Automatically detects and parses LCOV, Cobertura, JaCoCo, and Clover coverage files
- **Change tracking**: Compares PR coverage against main branch with visual delta indicators
- **Smart PR comments**: Single sticky comment that updates with each push - no spam
- **Dynamic badges**: Auto-updating coverage and change badges via GitHub Gists
- **Package organization**: Intelligent grouping and customizable package structure
- **Security focused**: Minimal permissions, input validation, and secure XML processing
- **Threshold validation**: Configurable coverage requirements with clear pass/fail indicators

## Quick Start

### 1. Basic PR Coverage Comments

Add coverage reports to your Pull Requests with this minimal setup:

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

This creates PR comments showing coverage metrics, but **without** change detection or badges.

### 2. Enhanced Setup with Change Detection

For coverage badges and change tracking, you have two options:

**Option A: GitHub Gist (Recommended)**
- Enables dynamic README badges
- External storage for baseline data
- Simpler permissions (no repository write access needed)

**Option B: File-Based Storage**  
- Stores baseline data in your repository
- No external dependencies
- Requires repository write permissions

#### Option A: GitHub Gist Setup

**Step 1: Create a GitHub Gist**
1. Go to [gist.github.com](https://gist.github.com)
2. Create a **public** gist with filename `coverage.json` and content: `{"coverage": 0}`
3. Note the Gist ID from the URL (e.g., `abc123def456789`)

**Step 2: Add Repository Secrets**
1. Go to your repository Settings → Secrets and variables → Actions
2. Add `COVERAGE_GIST_ID` with your gist ID
3. Add `GIST_TOKEN` with a [personal access token](https://github.com/settings/tokens) having `gist` scope

**Step 3: Update Your Workflow**
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
Create `.github/workflows/coverage-main.yml` to update baseline data:

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

#### Option B: File-Based Setup

**Step 1: Update PR Workflow**
```yaml
- name: Coverage Report with File-Based Detection
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    baseline-files: .github/coverage-data.json
    min-threshold: 80
```

**Step 2: Add Main Branch Workflow**
Create `.github/workflows/coverage-main.yml` with `contents: write` permission to update the data file. See [Setup Guide](./docs/SETUP-GUIDE.md#3-file-based-change-detection-alternative) for complete example.

### 3. Coverage Badge in README (Gist Only)

After setting up the Gist, add a dynamic coverage badge to your README:

```markdown
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/USERNAME/GIST_ID/raw/coverage-badge.json)
```

Replace `USERNAME` with your GitHub username and `GIST_ID` with your gist ID.

## What You'll Get

### PR Comments
With basic setup, you get clean, organized PR comments:

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

### Enhanced PR Comments (with Gist setup)
With change detection enabled, you get badges and delta indicators:

![Coverage](https://img.shields.io/badge/coverage-87.1%25-green) ![Changes](https://img.shields.io/badge/changes-+1.9%25-brightgreen)

**Overall Coverage:** 87.1% | **Changes:** +1.9% vs main branch

<details>
<summary><b>Code Coverage</b> | expand for full summary</summary>

[Same detailed table as above, plus change indicators for each package]

</details>

### Dynamic README Badge
A live badge that updates automatically:

![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/USERNAME/GIST_ID/raw/coverage-badge.json)

## Configuration Reference

### Required Inputs

| Input | Description | Example |
|-------|-------------|---------|
| `files` | Coverage file patterns (supports globs) | `coverage/lcov.info`<br>`**/cobertura.xml`<br>`coverage/*.xml` |

### Optional Inputs

| Input | Description | Default | Example |
|-------|-------------|---------|---------|
| `gist-id` | GitHub Gist ID for baseline storage (enables change badges) | - | `abc123def456789` |
| `github-token` | GitHub token for API access | `GITHUB_TOKEN` | `${{ secrets.GIST_TOKEN }}` |
| `min-threshold` | Minimum coverage for health indicators | `50` | `80` |
| `comment-mode` | Comment behavior: `update` (sticky) or `new` | `update` | `new` |
| `warn-only` | Don't fail on threshold violations | `false` | `true` |
| `baseline-files` | Baseline coverage files (alternative to gist) | - | `main-coverage.xml` |
| `thresholds` | Coverage requirements by category | - | `total:80\ndiff:75\nbranches:70` |

### Outputs

| Output | Description | Example |
|--------|-------------|---------|
| `coverage-pct` | Overall coverage percentage | `87.1` |
| `changes-coverage-pct` | Coverage for changed lines only | `91.3` |
| `coverage-delta` | Change vs baseline (when available) | `+1.9` |

### Supported Coverage Formats

The action automatically detects and parses these formats:

| Format | File Extensions | Common Tools |
|--------|----------------|--------------|
| **LCOV** | `.info` | Jest, Vitest, Karma, c8, nyc |
| **Cobertura** | `.xml` | .NET, Python (coverage.py), Maven |
| **JaCoCo** | `.xml` | Java, Kotlin, Scala |
| **Clover** | `.xml` | PHP (PHPUnit), JavaScript |

### Advanced Configuration

Create `.coverage-report.json` in your repository root for custom package grouping:

```json
{
  "groups": [
    {
      "name": "Core Components",
      "patterns": ["src/components/**"],
      "exclude": ["src/components/legacy/**"]
    },
    {
      "name": "Utilities",
      "patterns": ["src/utils/**", "src/helpers/**"]
    }
  ],
  "ui": {
    "expandFilesFor": ["Core Components"]
  }
}
```

See [Configuration Guide](./docs/CONFIGURATION.md) for detailed examples.

## Documentation

### Setup Guides
- **[Complete Setup Guide](./docs/SETUP-GUIDE.md)** - Step-by-step instructions for Basic and Enhanced setup
- **[Configuration Guide](./docs/CONFIGURATION.md)** - Advanced package grouping and customization
- **[Documentation Index](./docs/INDEX.md)** - Find the right documentation for your needs

### Example Workflows  
- **[Basic PR Coverage](./examples/basic-pr-coverage.yml)** - Simple coverage comments without badges
- **[Enhanced with Badges](./examples/enhanced-with-badges.yml)** - Full setup with change detection
- **[Multi-format Support](./examples/multi-format.yml)** - Using different coverage formats
- **[Monorepo Setup](./examples/monorepo-setup.yml)** - Configuration for monorepos

### Reference Documentation
- **[Token Flow Guide](./docs/TOKEN-FLOW.md)** - Understanding GitHub tokens and authentication
- **[Security Policy](./SECURITY.md)** - Security best practices and reporting
- **[Contributing Guide](./CONTRIBUTING.md)** - How to contribute to the project

## Common Use Cases

### JavaScript/TypeScript Projects (Jest, Vitest)
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

### Monorepo with Multiple Coverage Files
```yaml
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: |
      packages/*/coverage/lcov.info
      apps/*/coverage/cobertura.xml
    groups: |
      - name: "Frontend Packages"
        patterns: ["packages/ui/**", "packages/components/**"]
      - name: "Backend Services"
        patterns: ["apps/api/**", "apps/worker/**"]
```

## Security

HanCover Action is designed with security as a top priority:

- **Minimal permissions**: Only requires `pull-requests: write` and `contents: read`
- **Safe parsing**: XXE protection, input validation, and secure XML processing
- **Size limits**: Built-in protections against large file attacks (50MB per file, 200MB total)
- **Supply chain security**: Signed releases, dependency scanning, and regular audits

### Security Best Practices

**Pin to specific versions:**
```yaml
uses: farhan-ahmed1/hancover-action@v1.0.0  # ✅ Recommended
uses: farhan-ahmed1/hancover-action@main    # ❌ Avoid
```

**Use minimal permissions:**
```yaml
permissions:
  pull-requests: write  # For PR comments
  contents: read       # For repository access
  # Avoid granting unnecessary permissions
```

**Secure token management:**
```yaml
# Store sensitive tokens as repository secrets
github-token: ${{ secrets.GIST_TOKEN }}     # ✅ Secure
github-token: "ghp_your_token_here"         # ❌ Never do this
```

**Report security issues**: See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

## Troubleshooting

### Common Issues

**"No coverage files found"**
- Verify your coverage files are generated correctly
- Check file paths in the `files` input (supports glob patterns)
- Ensure your test command actually generates coverage

**"Failed to update gist"**
- Verify your `GIST_TOKEN` has `gist` scope
- Ensure the gist exists and is public
- Check that the gist ID is correct

**"Action fails on coverage threshold"**
- Adjust `min-threshold` value or improve test coverage
- Use `warn-only: true` to prevent failure while fixing coverage

**"Changes coverage is 0%"**
- Ensure your PR has actual code changes (not just config files)
- Check that the git diff is working correctly
- Verify coverage files include the changed files

### Getting Help

1. Check existing [GitHub Issues](https://github.com/farhan-ahmed1/hancover-action/issues)
2. Review the [documentation](#documentation)
3. Open a new issue with:
   - Your workflow file
   - Coverage file sample
   - Error messages
   - Action logs

## License

Apache-2.0 - see [LICENSE](LICENSE) for details.
