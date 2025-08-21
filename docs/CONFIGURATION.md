# Coverage Report Configuration

This guide explains how to customize coverage report organization and display using advanced configuration options.

## Smart Defaults

HanCover Action works perfectly without configuration. It automatically:

1. **Groups by first path segment**: `src/`, `test/`, `packages/`, etc.
2. **Promotes deeper when logical**: If `src/` contains 80%+ of files, shows `src/components/`, `src/utils/`, etc.
3. **Handles monorepos**: `packages/*/` becomes separate packages automatically

## Custom Configuration

Create `.coverage-report.json` in your repository root to override defaults:

### Basic Example

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
    },
    {
      "name": "Services",
      "patterns": ["src/services/**", "src/api/**"]
    }
  ],
  "ui": {
    "expandFilesFor": ["Core Components"]
  }
}
```

### Configuration Options

#### `groups` (array, optional)
Defines custom package groupings that override smart defaults.

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `name` | string | Display name for the package group | ✅ |
| `patterns` | string[] | Glob patterns to match files (supports `*` and `**`) | ✅ |
| `exclude` | string[] | Glob patterns to exclude from this group | ❌ |

**Processing Rules:**
- Groups are processed in order
- Files are assigned to the first matching group
- Excluded patterns take precedence over included patterns

#### `ui` (object, optional)
Controls visual presentation of coverage data.

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `expandFilesFor` | string[] | Package names to show expanded file listings | `[]` |

#### `fallback` (object, optional)
Controls smart default behavior when no custom groups are defined.

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `smartDepth` | string | `"auto"` \| `"top"` \| `"two"` | `"auto"` |
| `promoteThreshold` | number | Threshold (0-1) for promoting to deeper grouping | `0.8` |

**Smart Depth Options:**
- `"auto"`: Promotes one level deeper if single directory contains ≥80% of files
- `"top"`: Always groups by first path segment only  
- `"two"`: Always shows two levels deep

## Common Use Cases

### Monorepo with Multiple Packages

```json
{
  "groups": [
    {
      "name": "UI Components",
      "patterns": ["packages/ui/**", "packages/components/**"]
    },
    {
      "name": "Utilities & Tools", 
      "patterns": ["packages/utils/**", "packages/cli/**"]
    },
    {
      "name": "Web Applications",
      "patterns": ["apps/web/**", "apps/admin/**"]
    },
    {
      "name": "API Services",
      "patterns": ["apps/api/**", "apps/worker/**"]
    }
  ],
  "ui": {
    "expandFilesFor": ["UI Components", "API Services"]
  }
}
```

### Separating Test Code from Source

```json
{
  "groups": [
    {
      "name": "Core Application",
      "patterns": ["src/**"],
      "exclude": ["src/**/*.test.*", "src/**/*.spec.*"]
    },
    {
      "name": "Test Utilities", 
      "patterns": ["src/**/*.test.*", "src/**/*.spec.*", "test/**"]
    },
    {
      "name": "Build & Config",
      "patterns": ["build/**", "config/**", "scripts/**"]
    }
  ]
}
```

### Platform-Specific Grouping

```json
{
  "groups": [
    {
      "name": "Mobile Platform",
      "patterns": ["src/mobile/**", "src/react-native/**"]
    },
    {
      "name": "Web Platform",
      "patterns": ["src/web/**", "src/components/**"]
    },
    {
      "name": "Shared Libraries",
      "patterns": ["src/shared/**", "src/utils/**"]
    }
  ],
  "ui": {
    "expandFilesFor": ["Shared Libraries"]
  }
}
```

### Feature-Based Organization

```json
{
  "groups": [
    {
      "name": "Authentication",
      "patterns": ["src/auth/**", "src/login/**", "src/security/**"]
    },
    {
      "name": "Data Layer",
      "patterns": ["src/api/**", "src/database/**", "src/models/**"]
    },
    {
      "name": "User Interface",
      "patterns": ["src/components/**", "src/pages/**", "src/views/**"]
    }
  ]
}
```

## Advanced Configuration

### Using Workflow Configuration

Instead of `.coverage-report.json`, you can specify configuration inline:

```yaml
- name: Coverage Report
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    groups: |
      - name: "Frontend"
        patterns: ["src/components/**", "src/pages/**"]
      - name: "Backend"  
        patterns: ["src/api/**", "src/services/**"]
```

### Smart Depth Configuration

Control automatic grouping behavior:

```json
{
  "fallback": {
    "smartDepth": "two",
    "promoteThreshold": 0.7
  }
}
```

This configuration:
- Always shows two directory levels (`src/components/`, `src/utils/`)
- Promotes to deeper grouping when 70%+ of files are in one directory

### UI Customization

```json
{
  "ui": {
    "expandFilesFor": ["Core Components", "Critical Services"],
    "maxDeltaRows": 15,
    "minPassThreshold": 75
  }
}
```

This configuration:
- Shows file-level details for "Core Components" and "Critical Services"
- Shows up to 15 packages in delta comparison table
- Requires 75% coverage for "pass" health indicators

## Configuration Validation

The action validates your configuration and will provide helpful error messages:

```
❌ Configuration Error: Group "Frontend" has empty patterns array
❌ Configuration Error: Pattern "src/**" matches no files
⚠️  Configuration Warning: Group "Backend" excludes all matched files
```

## Troubleshooting

### No packages appear in report
- Check that your `patterns` match actual files in your coverage data
- Verify patterns use correct glob syntax (`**` for recursive matching)
- Enable debug output with `ACTIONS_STEP_DEBUG=true`

### Groups not showing expected files
- Remember that groups are processed in order
- Use `exclude` patterns to remove files from previous matches
- Test patterns against your actual file structure

### File expansion not working
- Ensure package names in `expandFilesFor` exactly match group names
- Check that packages actually contain multiple files

## Reference

### Complete Configuration Schema

```json
{
  "groups": [
    {
      "name": "string",
      "patterns": ["string[]"],
      "exclude": ["string[]"]  // optional
    }
  ],
  "ui": {
    "expandFilesFor": ["string[]"],
    "maxDeltaRows": "number",
    "minPassThreshold": "number"
  },
  "fallback": {
    "smartDepth": "auto" | "top" | "two", 
    "promoteThreshold": "number"
  }
}
```

### Glob Pattern Examples

| Pattern | Matches | 
|---------|---------|
| `src/**` | All files under `src/` recursively |
| `src/*` | Files directly in `src/` (not subdirectories) |
| `**/*.test.js` | All test files ending in `.test.js` |
| `packages/*/src/**` | All source files in any package |
| `apps/{web,api}/**` | Files in `apps/web/` or `apps/api/` |

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

## Security

- Configuration files are read-only JSON (no code execution)
- Glob patterns are processed safely with regex conversion
- All paths are normalized and validated
- No network requests for configuration
