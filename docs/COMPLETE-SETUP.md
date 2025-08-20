# Complete Badge Setup Guide

## 🎯 Overview

This system provides two badges:
1. **Coverage Badge**: Shows current coverage percentage
2. **Changes Badge**: Shows coverage delta (+/-) compared to main branch

## 📋 Step-by-Step Setup

### Step 1: Create GitHub Gist

1. Go to https://gist.github.com
2. Create a **public** gist with these files:

**File 1: `coverage.json`**
```json
{
  "coverage": 0,
  "timestamp": "2025-08-19T00:00:00.000Z",
  "branch": "main", 
  "commit": "initial"
}
```

**File 2: `coverage-badge.json`**
```json
{
  "schemaVersion": 1,
  "label": "coverage",
  "message": "0%",
  "color": "red"
}
```

3. Save and copy the **Gist ID** from URL (e.g., `abc123def456789`)

### Step 2: Create Personal Access Token

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Create new token with these scopes:
   - ✅ `gist` (required for updating gists)
   - ✅ `repo` (if private repo)
3. Copy the token (starts with `ghp_`)

### Step 3: Add Repository Secrets

In your repository settings → Secrets and variables → Actions:

- **`COVERAGE_GIST_ID`**: Your gist ID (`abc123def456789`)
- **`GIST_TOKEN`**: Your personal access token (`ghp_xxxxxxxxxxxx`)

### Step 4: Main Branch Workflow

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
          gist-id: ${{ secrets.COVERAGE_GIST_ID }}
          github-token: ${{ secrets.GIST_TOKEN }}
```

### Step 5: PR Workflow

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
          gist-id: ${{ secrets.COVERAGE_GIST_ID }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          min-threshold: 80
```

### Step 6: Add Badges to README

Add these to your README.md:

```markdown
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/USERNAME/GIST_ID/raw/coverage-badge.json)](https://github.com/USERNAME/REPO/actions)
```

Replace:
- `USERNAME`: Your GitHub username
- `GIST_ID`: Your gist ID
- `REPO`: Your repository name

## 🔄 How It Works

### Main Branch Flow:
```
Code Push → Tests Run → Coverage Generated → HanCover Action → Gist Updated
                                              ↓
                               Saves baseline coverage (85.2%) to gist
```

### PR Flow:
```
PR Opened → Tests Run → Coverage Generated → HanCover Action → Comment Posted
                                              ↓
                               1. Fetches baseline from gist (85.2%)
                               2. Calculates current coverage (87.1%) 
                               3. Shows delta badge (+1.9%)
```

### Token & Gist Access:
```
Workflow YAML → secrets.GIST_TOKEN → core.getInput() → GitHub API → Gist Updated
               secrets.COVERAGE_GIST_ID
```

## 🎨 Badge Examples

Once set up, you'll see:

**In PR Comments:**
- ![Coverage](https://img.shields.io/badge/coverage-87.1%25-green) ← Current coverage
- ![Changes](https://img.shields.io/badge/changes-+1.9%25-brightgreen) ← Delta vs main

**In README:**
- Dynamic badge that updates automatically from your gist

## 🐛 Troubleshooting

### No Changes Badge
- ✅ Ensure main branch workflow ran at least once
- ✅ Check gist has `coverage.json` with baseline data
- ✅ Verify `GIST_TOKEN` has `gist` scope

### Badge Not Updating  
- ✅ Check gist is **public** (private gists can't be used for badges)
- ✅ Verify `COVERAGE_GIST_ID` matches your actual gist ID
- ✅ Ensure token hasn't expired

### Permission Errors
- ✅ Token needs `gist` scope for gist access
- ✅ Main workflow needs the token in `github-token` input
- ✅ PR workflow can use `secrets.GITHUB_TOKEN` (default)

## 📊 Coverage File Support

The action supports these coverage formats automatically:
- **LCOV** (`.info` files) - Jest, Vitest, etc.
- **Cobertura** (`.xml` files) - .NET, Python
- **JaCoCo** (`.xml` files) - Java
- **Clover** (`.xml` files) - PHP

Example file paths:
```yaml
files: |
  coverage/lcov.info
  coverage/cobertura.xml
  build/reports/jacob/test/jacocoTestReport.xml
```
