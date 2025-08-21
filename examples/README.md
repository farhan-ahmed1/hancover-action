# HanCover Action Examples

Complete workflow examples for different setups and programming languages.

## Basic Setups

### [Basic PR Coverage](./basic-pr-coverage.yml)

Simple coverage reports in PR comments without change detection or badges.

- Single workflow file
- No external dependencies
- Coverage tables and health indicators

### [Enhanced with Badges](./enhanced-with-badges.yml)

Full-featured setup with change detection and dynamic badges.

- Coverage and change badges
- GitHub Gist integration
- Auto-updating README badges
- Change tracking vs main branch

## Advanced Configurations

### [Multi-format Support](./multi-format.yml)

Examples for different coverage formats and programming languages.

- LCOV (JavaScript/TypeScript)
- Cobertura (.NET, Python)
- JaCoCo (Java, Kotlin, Scala)
- Clover (PHP)

### [Monorepo Setup](./monorepo-setup.yml)

Configuration for complex projects with multiple packages.

- Multiple coverage files
- Custom package grouping
- Organized reporting structure

## Language-Specific Notes

### JavaScript/TypeScript

- **Coverage file**: `coverage/lcov.info`
- **Common tools**: Jest, Vitest, c8, nyc
- **Test command**: `npm test -- --coverage`

### .NET

- **Coverage file**: `coverage/**/coverage.cobertura.xml`
- **Test command**: `dotnet test --collect:"XPlat Code Coverage"`
- **Results directory**: `--results-directory coverage`

### Java (Maven)

- **Coverage file**: `target/site/jacoco/jacoco.xml`
- **Plugin**: JaCoCo Maven plugin
- **Test command**: `mvn test jacoco:report`

### Python

- **Coverage file**: `coverage.xml`
- **Tools**: coverage.py, pytest-cov
- **Commands**: `coverage run -m pytest && coverage xml`

### PHP

- **Coverage file**: `build/logs/clover.xml`
- **Tools**: PHPUnit with Clover format
- **Configuration**: Enable Clover logging in PHPUnit

## File-Based Alternative

For repositories that prefer not to use external Gists, see the file-based configuration in [Enhanced with Badges](./enhanced-with-badges.yml) which stores baseline data in the repository itself.

## Custom Package Grouping

All examples can be enhanced with custom package grouping by adding `.coverage-report.json`:

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
    }
  ],
  "ui": {
    "expandFilesFor": ["Core Components"]
  }
}
```

See [Configuration Guide](../docs/CONFIGURATION.md) for detailed configuration options.
