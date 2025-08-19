# Changes Badge Setup

The changes badge shows the coverage delta between your PR and the main branch using a simple JSON file stored in your repository.

## How It Works

1. **Main Branch**: When running on the main branch, the action updates a JSON file with the current coverage percentage
2. **PR Branches**: When running on PRs, the action reads the JSON file to get the main branch coverage and calculates the delta
3. **Badge Display**: Shows a visual badge with the coverage change (e.g., `+2.1%` or `-1.5%`)

## Setup

### 1. Add Coverage Data Path (Optional)

By default, the action uses `.github/coverage-data.json`. You can customize this:

```yaml
- name: HanCover Action
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    coverage-data-path: .github/coverage-data.json  # Custom path
```

### 2. Create Initial Coverage Data File

Create the file manually or let the action create it on the first main branch run:

```json
{
  "coverage": 75.0,
  "timestamp": "2025-08-19T12:00:00.000Z", 
  "branch": "main",
  "commit": "abc123def456789"
}
```

### 3. Workflow Configuration

#### Main Branch Workflow
Updates the coverage data file:

```yaml
name: Update Coverage Data
on:
  push:
    branches: [main]

permissions:
  contents: write

jobs:
  update-coverage-data:
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
          
      - name: Update Coverage Data File
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info
          coverage-data-path: .github/coverage-data.json
          
      - name: Commit updated coverage data
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

#### PR Workflow  
Displays the changes badge:

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
          fetch-depth: 0  # Need full history for git diff
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run tests with coverage
        run: npm test -- --coverage
          
      - name: Coverage Report with Changes Badge
        uses: farhan-ahmed1/hancover-action@v1
        with:
          files: coverage/lcov.info
          coverage-data-path: .github/coverage-data.json
```

## Badge Examples

The changes badge will appear next to your coverage badge:

- [![Coverage](https://img.shields.io/badge/coverage-78.5%25-green)](#) [![Changes](https://img.shields.io/badge/changes-+2.1%25-brightgreen)](#) - Coverage improved
- [![Coverage](https://img.shields.io/badge/coverage-76.2%25-green)](#) [![Changes](https://img.shields.io/badge/changes--1.3%25-red)](#) - Coverage decreased

## Data Structure

The coverage data JSON file contains:

```typescript
interface CoverageData {
  coverage: number;     // Coverage percentage (e.g., 75.0)
  timestamp: string;    // ISO timestamp of when data was updated
  branch: string;       // Branch name (typically "main")
  commit?: string;      // Git commit hash (optional)
}
```

## Benefits

- **Simple**: No external dependencies or services required
- **Version Controlled**: Coverage data is tracked in your repository
- **Reliable**: Works offline and doesn't depend on external endpoints
- **Transparent**: You can see exactly what coverage percentage is being used for comparison
- **Flexible**: Easy to modify or reset the baseline coverage

## Troubleshooting

### No Changes Badge Showing
- Ensure the coverage data file exists
- Check that the file path matches the `coverage-data-path` input
- Verify the JSON format is correct

### Incorrect Delta Calculation
- Check that the main branch workflow is updating the coverage data file
- Ensure the coverage data file is being committed to the repository
- Verify that the timestamp in the file is recent

### Permission Issues
- Make sure the main branch workflow has `contents: write` permission
- Ensure the commit step in the main branch workflow is configured correctly
