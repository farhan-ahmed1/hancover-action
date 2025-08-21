# Compatibility Matrix

This document provides an overview of HanCover's compatibility with different ecosystems, tools, and coverage formats.

## **Quick Reference**

| Ecosystem | Primary Format | Status | Setup Time |
|-----------|---------------|--------|------------|
| **Node.js** | LCOV | ✅ Fully Supported | 2 minutes |
| **.NET** | Cobertura | ✅ Fully Supported | 3 minutes |
| **Java** | JaCoCo/Cobertura | ✅ Fully Supported | 5 minutes |
| **Python** | Cobertura | ✅ Fully Supported | 3 minutes |
| **PHP** | Clover | ✅ Fully Supported | 5 minutes |
| **Go** | LCOV | ⚠️ Community Tested | 5 minutes |
| **Rust** | LCOV | ⚠️ Community Tested | 5 minutes |
| **Ruby** | LCOV | ⚠️ Community Tested | 5 minutes |

## **Detailed Compatibility**

### **Node.js Ecosystem**

| Tool | Version | Format | Status | Notes |
|------|---------|--------|--------|-------|
| **Jest** | 24+ | LCOV | ✅ | `--coverage --coverageReporters=lcov` |
| **Vitest** | 0.20+ | LCOV | ✅ | `--coverage --coverage.reporter=lcov` |
| **Mocha + NYC** | NYC 15+ | LCOV | ✅ | `nyc --reporter=lcov mocha` |
| **Mocha + c8** | c8 7+ | LCOV | ✅ | `c8 --reporter=lcov mocha` |
| **Karma** | 6+ | LCOV | ✅ | karma-coverage with lcov reporter |
| **Playwright** | 1.20+ | LCOV | ✅ | Via `@playwright/test` with coverage |
| **Cypress** | 10+ | LCOV | ✅ | Via `@cypress/code-coverage` |

**Example Configuration:**
```yaml
- run: npm test -- --coverage --coverageReporters=lcov
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
```

### **.NET Ecosystem**

| Tool | Version | Format | Status | Notes |
|------|---------|--------|--------|-------|
| **dotnet test** | .NET 5+ | Cobertura | ✅ | Requires XPlat Code Coverage |
| **coverlet** | 3.0+ | Cobertura | ✅ | MSBuild integration |
| **Fine Code Coverage** | 1.0+ | Cobertura | ✅ | Visual Studio extension |
| **JetBrains dotCover** | 2021+ | Cobertura | ⚠️ | Export to Cobertura format |

**Example Configuration:**
```yaml
- run: dotnet test --collect:"XPlat Code Coverage" --results-directory coverage
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/**/coverage.cobertura.xml
```

### **Java Ecosystem**

| Tool | Version | Format | Status | Notes |
|------|---------|--------|--------|-------|
| **JaCoCo (Maven)** | 0.8+ | JaCoCo XML | ✅ | `mvn jacoco:report` |
| **JaCoCo (Gradle)** | 0.8+ | JaCoCo XML | ✅ | `gradle jacocoTestReport` |
| **JaCoCo → Cobertura** | Any | Cobertura | ✅ | Via conversion tools |
| **Cobertura Maven** | 2.7+ | Cobertura | ✅ | Legacy but supported |
| **Scoverage (Scala)** | 1.4+ | Cobertura | ✅ | Scala projects |
| **Clover** | 4.0+ | Clover XML | ✅ | Enterprise coverage tool |

**Example Configuration (Maven):**
```yaml
- run: mvn test jacoco:report
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: target/site/jacoco/jacoco.xml
```

**Example Configuration (Gradle):**
```yaml
- run: ./gradlew test jacocoTestReport
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: build/reports/jacoco/test/jacocoTestReport.xml
```

### **Python Ecosystem**

| Tool | Version | Format | Status | Notes |
|------|---------|--------|--------|-------|
| **coverage.py** | 5.0+ | Cobertura | ✅ | `coverage xml` |
| **pytest-cov** | 3.0+ | Cobertura | ✅ | `--cov --cov-report=xml` |
| **nose2** | 0.10+ | Cobertura | ✅ | With cov-core plugin |
| **coverage.py** | 5.0+ | LCOV | ✅ | `coverage lcov` (newer versions) |

**Example Configuration:**
```yaml
- run: |
    pip install coverage pytest-cov
    coverage run -m pytest
    coverage xml
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage.xml
```

### **PHP Ecosystem**

| Tool | Version | Format | Status | Notes |
|------|---------|--------|--------|-------|
| **PHPUnit** | 9.0+ | Clover | ✅ | `--coverage-clover` |
| **PHPUnit** | 9.0+ | Cobertura | ✅ | `--coverage-cobertura` |
| **PCOV** | 1.0+ | Clover | ✅ | Faster than Xdebug |
| **Xdebug** | 3.0+ | Clover | ✅ | Traditional PHP coverage |
| **Infection** | 0.20+ | Clover | ✅ | Mutation testing tool |

**Example Configuration:**
```yaml
- run: vendor/bin/phpunit --coverage-clover coverage/clover.xml
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/clover.xml
```

### **Go Ecosystem**

| Tool | Version | Format | Status | Notes |
|------|---------|--------|--------|-------|
| **go test** | 1.16+ | Go Coverage | ⚠️ | Requires conversion to LCOV |
| **gocov** | Latest | LCOV | ⚠️ | Via gocov-lcov converter |
| **gcov2lcov** | Latest | LCOV | ⚠️ | Community tool |

**Example Configuration:**
```yaml
- run: |
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    # Convert to LCOV format (requires additional tools)
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage.lcov
```

### **Other Languages**

| Language | Tool | Format | Status | Notes |
|----------|------|--------|--------|-------|
| **Rust** | cargo-llvm-cov | LCOV | ⚠️ | `cargo llvm-cov --lcov` |
| **C/C++** | gcov/lcov | LCOV | ⚠️ | Traditional C coverage |
| **Swift** | Xcode | Cobertura | ⚠️ | Via xcresult conversion |
| **Kotlin** | JaCoCo | JaCoCo XML | ✅ | Same as Java ecosystem |
| **Scala** | Scoverage | Cobertura | ✅ | Well-supported |
| **Ruby** | SimpleCov | LCOV | ⚠️ | Via simplecov-lcov |

## **Format Support Details**

### **LCOV Format**
- **File Extension**: `.info`, `.lcov`
- **Auto-Detection**: ✅ Content-based detection
- **Line Coverage**: ✅ Full support
- **Branch Coverage**: ✅ Full support  
- **Function Coverage**: ✅ Full support
- **Large Files**: ✅ Up to 50MB per file
- **Security**: ✅ Path sanitization

### **Cobertura XML Format**
- **File Extension**: `.xml`
- **Auto-Detection**: ✅ XML structure detection
- **Line Coverage**: ✅ Full support
- **Branch Coverage**: ✅ Full support
- **Function Coverage**: ✅ Full support
- **Large Files**: ✅ Streaming parser available
- **Security**: ✅ XXE protection, DTD disabled

### **JaCoCo XML Format**
- **File Extension**: `.xml`
- **Auto-Detection**: ✅ JaCoCo-specific detection
- **Line Coverage**: ✅ Full support
- **Branch Coverage**: ✅ Full support
- **Function Coverage**: ✅ Method-level support
- **Large Files**: ✅ Efficient parsing
- **Security**: ✅ XXE protection, DTD disabled

### **Clover XML Format**
- **File Extension**: `.xml`
- **Auto-Detection**: ✅ Clover-specific detection
- **Line Coverage**: ✅ Full support
- **Branch Coverage**: ✅ Conditional coverage
- **Function Coverage**: ✅ Method-level support
- **Large Files**: ✅ Memory-efficient parsing
- **Security**: ✅ XXE protection, DTD disabled

## **Project Structure Support**

### **Monorepos**
```yaml
# Supports complex monorepo structures
with:
  files: |
    apps/*/coverage/lcov.info
    packages/*/coverage/cobertura.xml
  groups: |
    - name: "Frontend Apps"
      patterns: ["apps/web/**", "apps/mobile/**"]
    - name: "Backend Services"  
      patterns: ["apps/api/**", "apps/worker/**"]
    - name: "Shared Libraries"
      patterns: ["packages/**"]
```

### **Multi-Language Projects**
```yaml
# Mix different coverage formats
with:
  files: |
    frontend/coverage/lcov.info
    backend/coverage/cobertura.xml
    mobile/coverage/jacoco.xml
```

### **Complex Grouping**
```json
// .coverage-report.json
{
  "groups": [
    {
      "name": "Core Components",
      "patterns": ["src/components/**"],
      "exclude": ["src/components/legacy/**"]
    },
    {
      "name": "API Layer",
      "patterns": ["src/api/**", "src/graphql/**"]
    }
  ]
}
```

## **Known Limitations**

### **File Size Limits**
- **Per File**: 50MB (configurable)
- **Total**: 200MB (configurable)
- **Timeout**: 120 seconds (configurable)

### **Unsupported Formats**
- **Istanbul JSON**: Use LCOV export instead
- **gcov binary**: Use lcov conversion
- **Custom XML**: Must match supported schemas

### **Performance Considerations**
- **Large XML files**: May require streaming parser (v1.1.0)
- **Many small files**: Efficient batch processing
- **Complex monorepos**: Consider file filtering

## **Testing Your Setup**

### **Validation Checklist**
- [ ] Coverage files are generated correctly
- [ ] File paths match the `files` input pattern
- [ ] Coverage format is supported
- [ ] File sizes are within limits
- [ ] Required permissions are set

### **Debugging Tips**
```yaml
# Add debug information
- uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    # Add this for debugging
  env:
    ACTIONS_STEP_DEBUG: true
```

### **Common Issues**
1. **No coverage files found**: Check file paths and generation
2. **Parsing errors**: Verify coverage format and file integrity
3. **Missing permissions**: Ensure `pull-requests: write` permission
4. **File too large**: Adjust limits or filter coverage data

## **Contributing**

### **Adding New Tool Support**
To add support for a new tool:

1. Test with existing parsers
2. Document in compatibility matrix
3. Add example configuration
4. Submit PR with test coverage

### **Reporting Compatibility Issues**
When reporting issues:
- Include tool name and version
- Provide sample coverage file
- Share your workflow configuration
- Describe expected vs actual behavior

## **Status Legend**

- ✅ **Fully Supported**: Thoroughly tested, production-ready
- ⚠️ **Community Tested**: Works but may need configuration
- ❌ **Not Supported**: Not compatible or requires conversion
- 🚧 **In Development**: Planned for future release

---

**Last Updated**: August 2025  
**Version**: 1.0.0  
**Tested Environments**: GitHub Actions (Ubuntu, Windows, macOS)
