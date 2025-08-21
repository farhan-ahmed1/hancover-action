# HanCover Action Setup Guide

This guide provides step-by-step instructions for setting up HanCover Action in your repository.

## Choose Your Setup

### Option 1: Basic PR Coverage (5 minutes)
Get started quickly with coverage reports in PRs, but without change detection or badges.

**What you get:**
- Coverage tables in PR comments
- Package-based organization  
- Health indicators based on thresholds
- Sticky comments that update on each push

**What you don't get:**
- Coverage badges
- Change tracking vs main branch
- Dynamic README badges

**Setup:**
1. Copy [basic-pr-coverage.yml](../examples/basic-pr-coverage.yml) to `.github/workflows/pr-coverage.yml`
2. Adjust the `files` path to match your coverage output
3. Set your desired `min-threshold`

### Option 2: Enhanced with Change Detection (15 minutes)
Full-featured setup with badges, change tracking, and dynamic README badges.

**What you get:**
- Everything from Option 1, plus:
- Coverage badges in PR comments
- Change indicators (showing +/- vs main branch)
- Auto-updating README badge
- Baseline storage via GitHub Gist

**Setup:**
1. [Create a GitHub Gist](#creating-a-github-gist)
2. [Setup repository secrets](#setting-up-repository-secrets)  
3. [Add workflow files](#adding-workflow-files)
4. [Add README badge](#adding-readme-badge)

## Enhanced Setup Details

### Creating a GitHub Gist

1. Go to [gist.github.com](https://gist.github.com)
2. Create a **public** gist with:
   - **Filename:** `coverage.json`
   - **Content:** `{"coverage": 0}`
3. Save the gist and copy the **Gist ID** from the URL
   - Example URL: `https://gist.github.com/username/abc123def456789`
   - Gist ID: `abc123def456789`

### Setting up Repository Secrets

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Add these repository secrets:

| Secret Name | Value | Description |
|-------------|-------|-------------|
| `COVERAGE_GIST_ID` | `abc123def456789` | Your gist ID from the previous step |
| `GIST_TOKEN` | `ghp_xxxxxxxxxxxx` | Personal access token with `gist` scope |

**To create a personal access token:**
1. Go to [GitHub Settings](https://github.com/settings/tokens) → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Give it a descriptive name like "Coverage Gist Token"
4. Select the `gist` scope (and only that scope)
5. Click "Generate token" and copy the value

### Adding Workflow Files

Create these two workflow files in your repository:

**1. PR Coverage Workflow** (`.github/workflows/coverage-pr.yml`):
```yaml
name: PR Coverage with Change Detection
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
          gist-id: ${{ secrets.COVERAGE_GIST_ID }}
          github-token: ${{ secrets.GIST_TOKEN }}
          min-threshold: 80
```

**2. Main Branch Workflow** (`.github/workflows/coverage-main.yml`):
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

### Adding README Badge

Add this badge to your README.md file:

```markdown
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/USERNAME/GIST_ID/raw/coverage-badge.json)
```

Replace:
- `USERNAME` with your GitHub username
- `GIST_ID` with your gist ID

Example:
```markdown
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/farhan-ahmed1/abc123def456789/raw/coverage-badge.json)
```

### 3. File-Based Change Detection (Alternative)

If you prefer not to use GitHub Gists, you can store baseline coverage data in your repository:

**Step 1: Update Your PR Workflow**
```yaml
- name: Coverage Report with File-Based Detection
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    baseline-files: .github/coverage-data.json
    min-threshold: 80
```

**Step 2: Add Main Branch Workflow**
Create `.github/workflows/coverage-main.yml`:

```yaml
name: Update Coverage Data
on:
  push:
    branches: [main]

permissions:
  contents: write

jobs:
  update-coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      
      - run: npm ci
      - run: npm test -- --coverage
      
      - name: Update Coverage Data
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info
          coverage-data-path: .github/coverage-data.json

      - name: Commit coverage data
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          
          if ! git diff --quiet .github/coverage-data.json; then
            git add .github/coverage-data.json
            COVERAGE=$(jq -r '.coverage' .github/coverage-data.json)
            git commit -m "Update coverage data to ${COVERAGE}% [skip ci]"
            git push
          fi
```

**Pros:** No external dependencies, works entirely within your repository  
**Cons:** No dynamic README badge, requires repository write permissions

## Different Coverage Formats

The action automatically detects your coverage format. Just update the `files` path:

### JavaScript/TypeScript (Jest, Vitest)
```yaml
files: coverage/lcov.info
```

### .NET Projects
```yaml
files: coverage/**/coverage.cobertura.xml
```

### Java Projects (Maven)
```yaml
files: target/site/jacoco/jacoco.xml
```

### Python Projects
```yaml
files: coverage.xml
```

### Multiple Files
```yaml
files: |
  packages/*/coverage/lcov.info
  apps/*/coverage/cobertura.xml
```

## Custom Package Grouping

For monorepos or complex projects, create `.coverage-report.json` in your repository root:

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

See [Configuration Guide](./CONFIGURATION.md) for detailed examples.

## Troubleshooting

### "No coverage files found"
- Check that your test command generates coverage files
- Verify the `files` path matches your coverage output location
- Use glob patterns if files are in multiple locations

### "Failed to update gist"  
- Ensure your personal access token has `gist` scope
- Verify the gist exists and is public
- Double-check the gist ID in your repository secrets

### "Action fails on coverage threshold"
- Lower the `min-threshold` value or improve test coverage
- Use `warn-only: true` to prevent build failures while fixing coverage

### Coverage badges not updating
- Check that the main branch workflow is running successfully
- Verify the gist contains `coverage-badge.json` file
- Badge updates may take a few minutes to propagate

## Next Steps

- Review [Configuration Guide](./CONFIGURATION.md) for advanced features
- Check out [example workflows](../examples/) for different scenarios
- See [API Reference](./API-REFERENCE.md) for complete input/output documentation

## Getting Help

1. Check [existing issues](https://github.com/farhan-ahmed1/hancover-action/issues)
2. Review this documentation
3. Open a new issue with your workflow file and error details
