# Parser Test Reorganization

## Overview
The parser tests have been reorganized for better maintainability and clarity. Previously, we had an imbalanced structure with most Clover tests in `parsers.test.ts` and additional edge cases in a separate file.

## New Structure

### Before (Problems)
```
test/
├── parsers.test.ts           # Mixed tests, heavy Clover focus (19 tests)
├── clover-edge-cases.test.ts # Additional Clover tests (11 tests)
└── unified-parser.test.ts    # Auto-detection tests (4 tests)
```

**Issues:**
- ❌ Imbalanced test distribution (Clover: 30 tests, LCOV: 2 tests, Cobertura: 2 tests)
- ❌ Hard to find specific parser tests
- ❌ Clover tests split across multiple files
- ❌ No clear separation of concerns

### After (Improved)
```
test/
├── parsers.test.ts                    # Entry point that imports all parser tests
└── parsers/
    ├── lcov.test.ts                   # LCOV parser tests (5 tests)
    ├── cobertura.test.ts              # Cobertura parser tests (6 tests) 
    ├── clover.test.ts                 # Core Clover functionality (9 tests)
    ├── clover-edge-cases.test.ts      # Clover edge cases & robustness (12 tests)
    └── index.test.ts                  # Auto-detection & unified interface (13 tests)
```

**Benefits:**
- ✅ **Balanced Coverage**: Each parser has comprehensive, dedicated test files
- ✅ **Clear Organization**: Easy to find tests for any specific parser
- ✅ **Logical Grouping**: Core functionality vs edge cases clearly separated
- ✅ **Maintainability**: Changes to one parser don't affect other test files
- ✅ **Scalability**: Easy to add new parsers or expand existing test coverage

## Test Distribution

### LCOV Parser (`test/parsers/lcov.test.ts`) - 5 tests
- Basic LCOV file parsing
- String content parsing
- Empty file handling
- Function coverage support
- Branch coverage support

### Cobertura Parser (`test/parsers/cobertura.test.ts`) - 6 tests
- Basic XML parsing
- Empty XML handling
- Sample fixture testing
- Branch coverage in XML
- Method coverage in XML
- Malformed XML graceful handling

### Clover Parser - Core (`test/parsers/clover.test.ts`) - 9 tests
- Basic XML file parsing
- Complex multi-file/package structures
- String content parsing
- Empty XML handling
- Different line types (stmt, cond, method)
- Metrics prioritization
- Invalid XML structures
- Nested package structures
- Mixed single/array structures

### Clover Parser - Edge Cases (`test/parsers/clover-edge-cases.test.ts`) - 12 tests
**Security & Malformed Input:**
- XXE protection
- Path sanitization
- XML bomb protection

**Data Validation & Edge Cases:**
- Very large line numbers
- Malformed line numbers
- Empty files
- Negative counts
- Extremely large metrics

**Missing Attributes & Incomplete Data:**
- Missing required attributes
- Missing path/name attributes

**Unicode & Special Characters:**
- Unicode paths and package names
- Special characters in file paths

**Performance & Scale:**
- Large file performance testing

### Auto-Detection (`test/parsers/index.test.ts`) - 13 tests
**File-based Auto-detection:**
- LCOV file detection
- Clover XML detection
- Cobertura XML detection
- Empty file handling

**Content-based Auto-detection:**
- Format hints support
- Content sniffing without hints
- LCOV content detection
- Cobertura content detection
- Clover vs Cobertura distinction

**Format Priority & Edge Cases:**
- Ambiguous XML handling
- Malformed content graceful handling
- Empty content handling
- Format hint prioritization

## Usage

### Running All Parser Tests
```bash
npm test test/parsers.test.ts
```

### Running Specific Parser Tests
```bash
npm test test/parsers/lcov.test.ts
npm test test/parsers/cobertura.test.ts
npm test test/parsers/clover.test.ts
npm test test/parsers/clover-edge-cases.test.ts
npm test test/parsers/index.test.ts
```

### Test Totals
- **Total Parser Tests**: 45 tests
- **Overall Test Suite**: 209 tests (all passing)

## Architecture Benefits

### 1. **Separation of Concerns**
Each parser has its own dedicated test file, making it easier to:
- Add new test cases
- Debug parser-specific issues
- Understand parser capabilities
- Maintain test coverage

### 2. **Consistent Structure**
All parser test files follow the same pattern:
- Basic functionality tests
- Edge case handling
- Error conditions
- Security considerations (where applicable)

### 3. **Easy Maintenance**
- Changes to one parser don't affect other test files
- Clear file naming makes it obvious where to add new tests
- Consistent test organization across all parsers

### 4. **Comprehensive Coverage**
Each parser now has thorough test coverage including:
- Happy path scenarios
- Edge cases and error conditions
- Security validation
- Performance considerations

This reorganization provides a solid foundation for maintaining and extending the parser test suite as the project grows.
