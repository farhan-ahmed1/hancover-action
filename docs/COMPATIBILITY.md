# Compatibility Reference

Quick reference for supported coverage formats and programming languages.

## Supported Formats

| Language/Tool | Format | File Path | Test Command |
|---------------|--------|-----------|--------------|
| **JavaScript/TypeScript** | LCOV | `coverage/lcov.info` | `npm test -- --coverage` |
| **Jest, Vitest, c8, nyc** | LCOV | `coverage/lcov.info` | Auto-detected |
| **.NET** | Cobertura | `coverage/**/coverage.cobertura.xml` | `dotnet test --collect:"XPlat Code Coverage"` |
| **Java (Maven)** | JaCoCo | `target/site/jacoco/jacoco.xml` | `mvn test jacoco:report` |
| **Java (Gradle)** | JaCoCo | `build/reports/jacoco/test/jacocoTestReport.xml` | `./gradlew test jacocoTestReport` |
| **Python** | Cobertura | `coverage.xml` | `coverage run -m pytest && coverage xml` |
| **PHP** | Clover | `coverage.xml` or `build/logs/clover.xml` | `phpunit --coverage-clover=coverage.xml` |

## Format Auto-Detection

The action automatically detects coverage format based on file content. No configuration needed.

## Project Structure Support

### Monorepos
```yaml
with:
  files: |
    packages/*/coverage/lcov.info
    apps/*/coverage/cobertura.xml
```

### Multi-Language Projects
```yaml
with:
  files: |
    frontend/coverage/lcov.info
    backend/coverage/cobertura.xml
    mobile/coverage/jacoco.xml
```

### Custom Package Grouping
Create `.coverage-report.json` in repository root:
```json
{
  "groups": [
    {
      "name": "Frontend Apps",
      "patterns": ["apps/web/**", "apps/mobile/**"]
    },
    {
      "name": "Backend Services", 
      "patterns": ["apps/api/**", "apps/worker/**"]
    },
    {
      "name": "Shared Libraries",
      "patterns": ["packages/**"]
    }
  ]
}
```

## File Size Limits

- **Per File**: 50MB (configurable)
- **Total**: 200MB (configurable) 
- **Timeout**: 120 seconds (configurable)

## Unsupported Formats

- **Istanbul JSON**: Use LCOV export instead
- **gcov binary**: Use lcov conversion  
- **Custom XML**: Must match supported schemas

For setup examples, see [examples/workflows.yml](../examples/workflows.yml).
