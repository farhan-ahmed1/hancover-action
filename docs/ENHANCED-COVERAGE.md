# Enhanced Coverage Reporting Guide

This guide explains how to use the enhanced coverage reporting features with badges, collapsible comments, and baseline comparison.

## Features

✅ **Dynamic Badges**: Coverage and delta badges generated automatically  
✅ **Collapsible Comments**: Clean, organized PR comments with expandable details  
✅ **Baseline Comparison**: Compare PR coverage against main branch  
✅ **Health Indicators**: Visual health status based on configurable thresholds  
✅ **Project & Changes Coverage**: Separate tables for overall and diff coverage  
✅ **Single Comment**: Updates existing comment to avoid spam  

## Quick Start

### Basic Usage (No Baseline)

```yaml
- name: Coverage Report
  uses: your-org/hancover-action@v1
  with:
    files: coverage/lcov.info
    github-token: ${{ secrets.GITHUB_TOKEN }}
    min-threshold: 60
```

### Enhanced Usage (With Baseline Comparison)

```yaml
# 1. Generate coverage for both PR and main
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }

# PR coverage
- run: |
    npm ci
    npm test -- --coverage
    cp coverage/lcov.info pr.lcov

# Main coverage  
- run: |
    git checkout origin/main
    npm ci  
    npm test -- --coverage
    cp coverage/lcov.info main.lcov

# 2. Generate enhanced report
- name: Enhanced Coverage Report
  uses: your-org/hancover-action@v1
  with:
    files: pr.lcov
    baseline-files: main.lcov
    github-token: ${{ secrets.GITHUB_TOKEN }}
    thresholds: |
      total:80
      diff:75
      branches:70
    min-threshold: 60
```

## Comment Output

The enhanced comment includes:

### Badges (Always Visible)
- **Coverage Badge**: Current PR coverage percentage
- **Delta Badge**: Coverage change vs baseline (+0.5%, -1.2%, etc.)

### Collapsible Details
- **Project Coverage Table**: Overall PR coverage metrics
- **Code Changes Coverage Table**: Coverage of only changed lines  
- **Coverage by Group**: Breakdown by configured groups (optional)
- **Summary**: Detailed metrics and threshold status

## Configuration

### New Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `baseline-files` | Coverage files from main branch | (none) |
| `min-threshold` | Minimum % for health indicators | `50` |

### Existing Inputs (Enhanced)

| Input | Description | Example |
|-------|-------------|---------|
| `files` | PR coverage files | `coverage/lcov.info` |
| `thresholds` | Coverage requirements | `total:80\ndiff:75\nbranches:70` |
| `comment-mode` | Comment behavior | `update` (default) |

### New Outputs

| Output | Description |
|--------|-------------|
| `delta_coverage` | Coverage change vs baseline |

## Workflow Examples

### 1. LCOV with Baseline

```yaml
jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      
      # PR coverage
      - name: Test PR
        run: |
          npm ci
          npm test -- --coverage
          mv coverage/lcov.info pr.lcov
      
      # Main coverage
      - name: Test main
        run: |
          git checkout origin/main
          npm ci
          npm test -- --coverage  
          mv coverage/lcov.info main.lcov
          git checkout -
      
      # Report
      - uses: your-org/hancover-action@v1
        with:
          files: pr.lcov
          baseline-files: main.lcov
          github-token: ${{ secrets.GITHUB_TOKEN }}
          min-threshold: 70
```

### 2. Cobertura with Groups

```yaml
- uses: your-org/hancover-action@v1
  with:
    files: coverage/cobertura-coverage.xml
    github-token: ${{ secrets.GITHUB_TOKEN }}
    groups: |
      - name: "Core"
        pattern: "src/core/**"
      - name: "Utils"  
        pattern: "src/utils/**"
    thresholds: |
      total:85
      diff:80
    min-threshold: 75
```

### 3. Multiple File Types

```yaml
- uses: your-org/hancover-action@v1
  with:
    files: |
      coverage/lcov.info
      packages/*/coverage/cobertura.xml
      apps/*/coverage/clover.xml
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Badge Colors

Badges automatically use appropriate colors based on coverage:

- **90%+**: `brightgreen` 🟢
- **80-89%**: `green` 🟢  
- **70-79%**: `yellowgreen` 🟡
- **60-69%**: `yellow` 🟡
- **50-59%**: `orange` 🟠
- **<50%**: `red` 🔴

## Advanced Features

### Persistent README Badges

To add badges to your README that update on main branch pushes:

```yaml
# .github/workflows/main-coverage.yml
on:
  push:
    branches: [main]

jobs:
  badges:
    runs-on: ubuntu-latest  
    steps:
      - uses: actions/checkout@v4
      - run: |
          npm ci
          npm test -- --coverage
      
      # This would require additional implementation
      - name: Update README badges
        uses: your-org/hancover-action@v1
        with:
          files: coverage/lcov.info
          update-readme-badges: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Custom Health Thresholds

```yaml
- uses: your-org/hancover-action@v1
  with:
    files: coverage/lcov.info
    min-threshold: 85  # Strict health requirements
    thresholds: |
      total:90
      diff:95
      branches:80
```

## Troubleshooting

### Common Issues

1. **No delta badge**: Ensure `baseline-files` is provided
2. **No branch coverage**: Your coverage tool may not generate branch data
3. **Comment not updating**: Check `github-token` permissions
4. **Large coverage files**: Adjust `max-bytes-per-file` and `max-total-bytes`

### Debug Mode

Enable debug logging:

```yaml
- uses: your-org/hancover-action@v1
  with:
    files: coverage/lcov.info
    github-token: ${{ secrets.GITHUB_TOKEN }}
  env:
    ACTIONS_STEP_DEBUG: true
```

## Migration from Basic Comments

If you're upgrading from the basic comment format:

1. **Comments will be replaced**: The new format uses a different marker
2. **Add `min-threshold`**: Set appropriate health indicator threshold  
3. **Consider `baseline-files`**: Enable delta badges with baseline comparison
4. **Update thresholds**: The new format shows thresholds more prominently

## Example Output

The enhanced comment will look like:

```markdown
[![Coverage](https://img.shields.io/badge/Coverage-92.7%25-brightgreen)](#)
[![Δ coverage](https://img.shields.io/badge/%CE%94%20coverage-%2B0.5%25-brightgreen)](#)

<details>
<summary><b>Code Coverage</b> &nbsp;|&nbsp; <i>expand for full summary</i></summary>

<br/>

### Project Coverage (PR)
| Package | Line Rate | Branch Rate | Health |
|---|---:|---:|:---:|
| main | 92.7% | 65.8% | ✅ |
| **Summary** | **92.7% (179 / 193)** | **65.8% (100 / 152)** | **✅** |

_Minimum pass threshold is 60.0%_

---

### Code Changes Coverage  
| Package | Line Rate | Branch Rate | Health |
|---|---:|---:|:---:|
| main | 91.2% | N/A | ✅ |
| **Summary** | **91.2% (83 / 91)** | **N/A** | **✅** |

_Minimum pass threshold is 60.0%_

### 📋 Summary
- **Lines Covered**: 179/193
- **Changed Lines Covered**: 83/91  
- **Coverage Delta**: +0.5%
- **Thresholds**: {"total":80,"diff":75,"branches":70}

✅ **All coverage thresholds met**
</details>
```
