# Coverage Badge Setup

This guide shows how to set up automated coverage badges that follow GitHub best practices by avoiding direct commits to the main branch.

## Quick Setup (Recommended)

### Option 1: Simple Static Badge (Easiest)

**Step 1:** Add this workflow to your repository (`.github/workflows/coverage-badge.yml`):

```yaml
name: Coverage Badge

on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  coverage-badge:
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

      - name: Generate coverage badge data
        id: coverage
        run: |
          # Extract coverage percentage from test output
          COVERAGE_OUTPUT=$(npm test -- --coverage 2>&1)
          COVERAGE=$(echo "$COVERAGE_OUTPUT" | grep "All files" | awk '{print $4}' | head -1 | cut -d. -f1)
          
          if [ -z "$COVERAGE" ]; then
            echo "Could not extract coverage percentage"
            exit 1
          fi
          
          # Determine color based on coverage
          if [ $COVERAGE -ge 90 ]; then
            COLOR="brightgreen"
          elif [ $COVERAGE -ge 80 ]; then
            COLOR="green"  
          elif [ $COVERAGE -ge 70 ]; then
            COLOR="yellow"
          elif [ $COVERAGE -ge 60 ]; then
            COLOR="orange"
          else
            COLOR="red"
          fi
          
          echo "coverage=$COVERAGE" >> $GITHUB_OUTPUT
          echo "color=$COLOR" >> $GITHUB_OUTPUT
          echo "Coverage: $COVERAGE% (Color: $COLOR)"

      - name: Create coverage badge JSON
        run: |
          cat > coverage-badge.json << EOF
          {
            "schemaVersion": 1,
            "label": "coverage",
            "message": "${{ steps.coverage.outputs.coverage }}%",
            "color": "${{ steps.coverage.outputs.color }}"
          }
          EOF

      - name: Upload coverage badge data
        uses: actions/upload-artifact@v4
        with:
          name: coverage-badge
          path: coverage-badge.json
          retention-days: 30
```

**Step 2:** Add this badge to your README.md (update the percentage as needed):
```markdown
![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)
```

**Step 3:** Update the badge manually when coverage changes, or use one of the dynamic options below.

### Option 2: Dynamic Badge with Gist (More Advanced)

**Step 1:** Create a public GitHub Gist with a file named `coverage.json`

**Step 2:** Add these secrets to your repository:
- `GIST_TOKEN`: A GitHub Personal Access Token with `gist` scope
- `GIST_ID`: The ID of your gist (from the URL)

**Step 3:** Add this workflow (`.github/workflows/coverage-badge.yml`):

```yaml
name: Coverage Badge

on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  coverage-badge:
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

      - name: Generate coverage percentage
        id: coverage
        run: |
          COVERAGE_OUTPUT=$(npm test -- --coverage 2>&1)
          COVERAGE=$(echo "$COVERAGE_OUTPUT" | grep "All files" | awk '{print $4}' | head -1 | cut -d. -f1)
          echo "percentage=$COVERAGE" >> $GITHUB_OUTPUT

      - name: Update coverage badge
        uses: schneegans/dynamic-badges-action@v1.7.0
        with:
          auth: ${{ secrets.GIST_TOKEN }}
          gistID: ${{ secrets.GIST_ID }}
          filename: coverage.json
          label: coverage
          message: ${{ steps.coverage.outputs.percentage }}%
          color: >
            ${{
              steps.coverage.outputs.percentage >= 90 && 'brightgreen' ||
              steps.coverage.outputs.percentage >= 80 && 'green' ||
              steps.coverage.outputs.percentage >= 70 && 'yellow' ||
              steps.coverage.outputs.percentage >= 60 && 'orange' ||
              'red'
            }}
```

**Step 4:** Add this badge to your README.md:
```markdown
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/YOUR_USERNAME/YOUR_GIST_ID/raw/coverage.json)
```

### Option 3: Third-Party Services (Easiest Overall)

Use dedicated coverage services that handle badges automatically:

- **Codecov**: Add `codecov/codecov-action@v4` to your workflow
- **Coveralls**: Add `coverallsapp/github-action@v2` to your workflow  
- **Codacy**: Add `codacy/codacy-coverage-reporter-action@v1` to your workflow

## Why This Approach?

✅ **No direct commits to main**: Follows GitHub best practices  
✅ **No branch protection conflicts**: Works with any repository setup  
✅ **Simple user setup**: Copy workflow, add badge, done  
✅ **Secure**: Minimal permissions required  
✅ **Flexible**: Choose the option that fits your needs  

## Migration from Old Setup

If you were using the previous file-based approach with coverage-data.json:

1. **Remove old files** (if they exist):
   - `.github/workflows/update-coverage-data.yml`
   - `.github/coverage-data.json`

2. **Choose one of the options above**

3. **Update your README badge URL**

The HanCover action will continue to work exactly the same for PR coverage reports - this only affects how you generate coverage badges for your main branch.

## Troubleshooting

### Badge not updating
- Check that your workflow runs successfully on main branch pushes
- Verify the coverage extraction command works with your test setup
- For gist-based badges, ensure your token has the correct permissions

### Coverage extraction fails
- Adjust the grep/awk command to match your test runner's output format
- For Jest: `grep "All files" | awk '{print $4}'`
- For Vitest: `grep "All files" | awk '{print $4}'`
- For other runners: Check the exact output format

### Wrong coverage percentage
- Make sure you're running the same test command that generates your coverage files
- Verify the coverage percentage matches what you see in your coverage reports
