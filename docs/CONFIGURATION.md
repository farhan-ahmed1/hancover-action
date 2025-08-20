# Coverage Report Configuration

This document explains how to configure the enhanced coverage reporting features introduced to better organize and display your coverage data.

## Quick Start

The action works perfectly without any configuration using smart defaults. However, you can create a `.coverage-report.json` file in your repository root to customize the behavior.

### Basic Configuration

```json
{
    "groups": [
        {
            "name": "src/parsers", 
            "patterns": ["src/parsers/**"]
        },
        {
            "name": "src",
            "patterns": ["src/**"],
            "exclude": ["src/parsers/**"]
        }
    ],
    "ui": {
        "expandFilesFor": ["src/parsers"]
    }
}
```

## Configuration Options

### `groups` (optional)
Defines custom package groupings that override the smart defaults.

- **`name`**: Display name for the package group
- **`patterns`**: Array of glob patterns to match files (supports `*` and `**`)
- **`exclude`**: Array of glob patterns to exclude files (optional)

Rules are processed in order, and files are assigned to the first matching rule.

### `fallback` (optional)
Controls the smart default behavior when no custom groups are defined.

- **`smartDepth`**: `"auto"` | `"top"` | `"two"` (default: `"auto"`)
  - `"auto"`: Promotes one level deeper if a single directory contains ≥80% of files
  - `"top"`: Always group by first path segment only
  - `"two"`: Always show two levels deep

- **`promoteThreshold`**: Number between 0-1 (default: `0.8`)
  - Threshold for promoting to deeper grouping in auto mode

### `ui` (optional)
Controls display and interaction features.

- **`expandFilesFor`**: Array of package names that should show expandable file details
- **`maxDeltaRows`**: Maximum number of packages to show in delta table before collapsing (default: `10`)
- **`minPassThreshold`**: Minimum coverage percentage for "pass" health indicators (default: `50`)

## Features

### Smart Defaults (No Config Required)

Without any configuration, the action automatically:

1. **Groups by first path segment**: `src`, `test`, `packages`, etc.
2. **Promotes deeper when appropriate**: If `src/` contains ≥80% of files, shows `src/components`, `src/utils`, etc.
3. **Handles monorepos naturally**: `packages/*/` becomes separate packages

### Enhanced Report Structure

The coverage report now includes:

1. **Top badges** (unchanged)
2. **Top-level Package Summary** - high-level overview by first path segment
3. **Detailed Coverage by Package** - your configured package groupings
4. **Expandable File Tables** - click to see individual files within packages
5. **Coverage Delta** - changes vs main branch (if available)

### Example Output Structure

```
## Coverage Report

[Coverage Badge] [Changes Badge] [Delta Badge]

Overall Coverage: 63.0% | Lines Covered: 852/1353

### Top-level Packages (Summary)
| Package | Statements | Branches | Functions | Health |
|---------|------------|----------|-----------|--------|
| src     | 66.1% (580/878) | 78.9% (153/194) | 79.1% (34/43) | ✅ |
| tests   | 92.0% (230/250) | 70.0% (70/100) | 95.0% (19/20) | ✅ |

<details>
<summary>Detailed Coverage by Package</summary>

| Package | Statements | Branches | Functions | Health |
|---------|------------|----------|-----------|--------|
| src     | 65.2% (534/818) | 78.8% (141/179) | 78.1% (25/32) | ✅ |
| src/parsers | 83.0% (254/306) | 67.6% (50/74) | 100.0% (9/9) | ✅ |

<details>
<summary>Files in <code>src/parsers</code></summary>

| File | Statements | Branches | Functions | Health |
|------|------------|----------|-----------|--------|
| src/parsers/clover.ts | 82.3% (51/62) | 66.7% (8/12) | 100% (2/2) | ✅ |
| src/parsers/lcov.ts | 84.1% (203/241) | 68.0% (42/62) | 100% (7/7) | ✅ |

</details>

</details>
```

## Common Use Cases

### Separating Parsers from Main Code

```json
{
    "groups": [
        {
            "name": "src/parsers",
            "patterns": ["src/parsers/**"]
        },
        {
            "name": "src",
            "patterns": ["src/**"],
            "exclude": ["src/parsers/**"]
        }
    ],
    "ui": {
        "expandFilesFor": ["src/parsers"]
    }
}
```

### Monorepo with Multiple Packages

```json
{
    "groups": [
        {
            "name": "packages/ui",
            "patterns": ["packages/ui/**"]
        },
        {
            "name": "packages/utils", 
            "patterns": ["packages/utils/**"]
        },
        {
            "name": "apps/web",
            "patterns": ["apps/web/**"]
        }
    ],
    "ui": {
        "expandFilesFor": ["packages/ui", "packages/utils"]
    }
}
```

### Platform-Specific Grouping

```json
{
    "groups": [
        {
            "name": "mobile",
            "patterns": ["src/mobile/**", "src/react-native/**"]
        },
        {
            "name": "web",
            "patterns": ["src/web/**", "src/components/**"]
        },
        {
            "name": "shared",
            "patterns": ["src/shared/**", "src/utils/**"]
        }
    ]
}
```

## Backwards Compatibility

All existing coverage reports will continue to work without any changes. The new features are completely opt-in and non-breaking.

## Security

- Configuration files are read-only JSON (no code execution)
- Glob patterns are processed safely with regex conversion
- All paths are normalized and validated
- No network requests for configuration
