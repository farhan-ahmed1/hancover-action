# Gist-Based Coverage Setup

This guide shows how to set up coverage badges using GitHub Gists for baseline storage.

## Quick Setup

### 1. Create a GitHub Gist

1. Go to https://gist.github.com
2. Create a new public gist
3. Name it something like "coverage-data" 
4. Add a file called `coverage.json` with initial content:
   ```json
   {
     "coverage": 0,
     "timestamp": "2025-08-19T00:00:00.000Z",
     "branch": "main",
     "commit": "initial"
   }
   ```
5. Save the gist and copy the Gist ID from the URL (e.g., `abc123def456`)

### 2. Set up GitHub Secrets

Add these secrets to your repository:
- `GIST_ID`: The ID of your gist (e.g., `abc123def456`)
- `GITHUB_TOKEN`: A personal access token with `gist` scope

### 3. Create Workflow Files

#### Main Branch Workflow (`.github/workflows/coverage-main.yml`)
Updates the baseline coverage data:

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
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

#### PR Workflow (`.github/workflows/coverage-pr.yml`)
Shows coverage changes and posts PR comments:

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
          min-threshold: 80
```

## How It Works

1. **Main Branch**: When code is pushed to main, the action:
   - Runs your tests and generates coverage
   - Calculates the overall coverage percentage  
   - Updates the Gist with the new baseline coverage data

2. **Pull Requests**: When a PR is opened/updated, the action:
   - Runs tests and generates coverage for the PR
   - Fetches the baseline coverage from the Gist
   - Calculates the coverage delta (change from main)
   - Posts a comment with coverage report and change badge

3. **Badges**: The action generates:
   - **Coverage Badge**: Shows current PR coverage percentage
   - **Changes Badge**: Shows coverage delta (+2.1% or -1.5%) compared to main

## Badge URLs

Once set up, you can use these badge URLs in your README:

```markdown
[![Coverage](https://gist.githubusercontent.com/USERNAME/GIST_ID/raw/coverage-badge.json)](https://github.com/OWNER/REPO/actions)
```

The action automatically updates both `coverage.json` (data) and `coverage-badge.json` (Shields.io format) in your Gist.

## Troubleshooting

### No Changes Badge Appearing
- Ensure `gist-id` is set in your workflow
- Verify the GITHUB_TOKEN has `gist` scope
- Check that the main branch workflow has run at least once

### Badge Not Updating
- Verify the Gist ID is correct
- Check that the token has proper permissions
- Look at the workflow logs for error messages

### Wrong Coverage Values
- Ensure your test command generates coverage files in the expected location
- Check the `files` input matches your coverage file paths
- Verify coverage format is supported (LCOV, Cobertura, JaCoCo, Clover)
