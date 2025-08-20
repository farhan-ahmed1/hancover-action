# Coverage Badge and Changes Badge Setup Guide

This guide will help you set up dynamic coverage badges and changes badges for your repository using the HanCover Action.

## Overview

The HanCover Action supports two types of badges:

1. **Coverage Badge**: Shows current coverage percentage
2. **Changes Badge**: Shows coverage delta between PR and main branch

## Setup Options

### Option 1: Using GitHub Gist (Recommended)

This approach stores coverage data in a GitHub Gist, enabling dynamic badges that update automatically.

#### Step 1: Create a GitHub Gist

1. Go to [gist.github.com](https://gist.github.com)
2. Create a new gist with:
   - Filename: `coverage.json`
   - Content: `{"coverage": 0, "timestamp": "", "branch": "main", "commit": ""}`
   - Make it **public** (required for badges)
3. Note the Gist ID from the URL (e.g., `abc123def456789`)

#### Step 2: Create GitHub Personal Access Token

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Create a new token with `gist` scope
3. Copy the token (you'll need it for the workflow)

#### Step 3: Add Repository Secrets

Add these secrets to your repository (Settings → Secrets and variables → Actions):

- `GIST_TOKEN`: Your personal access token
- `GIST_ID`: Your gist ID

#### Step 4: Main Branch Workflow

Create `.github/workflows/coverage-main.yml`:

```yaml
name: Update Coverage Data
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  update-coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          
      - name: Install dependencies
        run: npm ci

      - name: Run tests with coverage
        run: npm test -- --coverage

      - name: Update Coverage Data
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info
          gist-id: ${{ secrets.GIST_ID }}
          github-token: ${{ secrets.GIST_TOKEN }}
```

#### Step 5: PR Workflow

Create `.github/workflows/coverage-pr.yml`:

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
          
      - name: Install dependencies
        run: npm ci

      - name: Run tests with coverage
        run: npm test -- --coverage

      - name: Coverage Report
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info
          gist-id: ${{ secrets.GIST_ID }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

#### Step 6: Add Badges to README

Add these to your README.md:

```markdown
[![Coverage](https://gist.githubusercontent.com/YOUR_USERNAME/YOUR_GIST_ID/raw/coverage-badge.json)](https://github.com/YOUR_USERNAME/YOUR_REPO/actions)
```

### Option 2: Using Repository File

This approach stores coverage data in a JSON file in your repository.

#### Step 1: Main Branch Workflow

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
          
      - name: Install dependencies
        run: npm ci

      - name: Run tests with coverage
        run: npm test -- --coverage

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
          else
            echo "No changes to coverage data file"
          fi
```

#### Step 2: PR Workflow

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
        with:
          fetch-depth: 0  # Need full history to access main branch data
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          
      - name: Install dependencies
        run: npm ci

      - name: Run tests with coverage
        run: npm test -- --coverage

      - name: Coverage Report
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info
          coverage-data-path: .github/coverage-data.json
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Badge Examples

Once set up, your PR comments will include badges like:

- **Coverage Badge**: ![Coverage](https://img.shields.io/badge/coverage-85.2%25-green)
- **Changes Badge**: ![Changes](https://img.shields.io/badge/changes-+2.1%25-brightgreen)

## Troubleshooting

### Changes Badge Not Showing

1. **Check if main branch coverage data exists**: The changes badge requires baseline coverage data
2. **Verify workflow runs on main**: Make sure the main branch workflow has run at least once
3. **Check gist permissions**: If using gist, ensure it's public
4. **Verify token permissions**: Ensure your token has `gist` scope

### Coverage Data Not Updating

1. **Check workflow permissions**: Main branch workflow needs `contents: write` for repository files
2. **Verify gist ID**: Double-check the gist ID in your secrets
3. **Check token expiration**: Ensure your personal access token hasn't expired

### Common Issues

1. **File paths**: Make sure coverage file paths match your test setup
2. **Branch names**: If you use `master` instead of `main`, update the workflows accordingly
3. **Coverage format**: HanCover supports LCOV and Cobertura formats automatically

## Advanced Configuration

### Custom Coverage Data Path

```yaml
- name: Coverage Report
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    coverage-data-path: custom/path/coverage.json
```

### Multiple Coverage Files

```yaml
- name: Coverage Report
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: |
      frontend/coverage/lcov.info
      backend/coverage/cobertura.xml
```

### Custom Minimum Threshold

```yaml
- name: Coverage Report
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    min-threshold: 80
```

This will set the minimum threshold for the health indicators to 80%.
