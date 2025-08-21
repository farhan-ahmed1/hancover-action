# HanCover Action Documentation Index

Welcome to the HanCover Action documentation. This index helps you find the right information based on what you're trying to accomplish.

## Quick Navigation

### Getting Started
- **[README](../README.md)** - Overview, features, and basic examples
- **[Setup Guide](./SETUP-GUIDE.md)** - Complete setup instructions (Basic vs Enhanced)

### Configuration & Customization  
- **[Configuration Guide](./CONFIGURATION.md)** - Advanced package grouping and report customization
- **[API Reference](./API-REFERENCE.md)** - Complete input/output reference and configuration options
- **[Token Flow Guide](./TOKEN-FLOW.md)** - Understanding GitHub tokens and authentication

### Example Workflows
- **[Basic PR Coverage](../examples/basic-pr-coverage.yml)** - Simple coverage comments
- **[Enhanced with Badges](../examples/enhanced-with-badges.yml)** - Full setup with change detection
- **[Multi-format Support](../examples/multi-format.yml)** - Different coverage formats (LCOV, Cobertura, JaCoCo, Clover)
- **[Monorepo Setup](../examples/monorepo-setup.yml)** - Complex project configuration

### Reference & Support
- **[Security Policy](../SECURITY.md)** - Security best practices and vulnerability reporting
- **[Contributing Guide](../CONTRIBUTING.md)** - How to contribute to the project
- **[GitHub Issues](https://github.com/farhan-ahmed1/hancover-action/issues)** - Bug reports and feature requests

## I Want To...

### Set Up Coverage Reports
- **First time setup**: Start with [Setup Guide](./SETUP-GUIDE.md)
- **Just PR comments**: Use [Basic PR Coverage](../examples/basic-pr-coverage.yml)
- **With badges and change tracking**: Use [Enhanced with Badges](../examples/enhanced-with-badges.yml)

### Use Different Programming Languages
- **JavaScript/TypeScript**: [Basic example](../examples/basic-pr-coverage.yml) + adjust `files` to `coverage/lcov.info`
- **.NET**: [Multi-format example](../examples/multi-format.yml) + use `coverage/**/coverage.cobertura.xml`
- **Java**: [Multi-format example](../examples/multi-format.yml) + use `target/site/jacoco/jacoco.xml`
- **Python**: [Multi-format example](../examples/multi-format.yml) + use `coverage.xml`
- **Multiple formats**: [Multi-format example](../examples/multi-format.yml)

### Customize Coverage Reports
- **Basic grouping**: Add `.coverage-report.json` - see [Configuration Guide](./CONFIGURATION.md)
- **Monorepo/complex projects**: See [Monorepo Setup](../examples/monorepo-setup.yml)
- **Custom thresholds**: Use `min-threshold` and `thresholds` inputs - see [API Reference](./API-REFERENCE.md)

### Troubleshoot Issues
- **Common problems**: Check [Setup Guide troubleshooting](./SETUP-GUIDE.md#troubleshooting)
- **Action not working**: Review [README troubleshooting](../README.md#troubleshooting)  
- **Gist/badge issues**: See [Token Flow Guide](./TOKEN-FLOW.md)
- **Still stuck**: Open an [issue](https://github.com/farhan-ahmed1/hancover-action/issues)

### Understand How It Works
- **Authentication flow**: [Token Flow Guide](./TOKEN-FLOW.md)
- **Security considerations**: [Security Policy](../SECURITY.md)
- **Supported formats**: [README coverage formats](../README.md#configuration-reference)
- **Package grouping logic**: [Configuration Guide](./CONFIGURATION.md)

## Documentation

### Current Documentation
✅ **[README.md](../README.md)** - Main overview and quick start guide  
✅ **[Setup Guide](./SETUP-GUIDE.md)** - Complete setup instructions  
✅ **[Configuration Guide](./CONFIGURATION.md)** - Advanced configuration options  
✅ **[Token Flow Guide](./TOKEN-FLOW.md)** - Authentication and token setup  
✅ **[Example Workflows](../examples/)** - Ready-to-use workflow examples  

## Contributing to Documentation

Found something unclear or missing? We welcome improvements:

1. **Quick fixes**: Edit directly on GitHub and submit a PR
2. **Larger changes**: Open an issue first to discuss the approach
3. **New examples**: Add to the `examples/` directory with clear comments
4. **Follow the style**: Clear headings, practical examples, troubleshooting sections

See [Contributing Guide](../CONTRIBUTING.md) for detailed contribution instructions.

## External Resources

- **GitHub Actions Documentation**: [Official Actions Docs](https://docs.github.com/en/actions)
- **Coverage Formats**:
  - [LCOV Format](http://ltp.sourceforge.net/coverage/lcov/genhtml.1.php)
  - [Cobertura Format](https://cobertura.github.io/cobertura/)
  - [JaCoCo Format](https://www.jacoco.org/jacoco/)
  - [Clover Format](https://openclover.org/)
- **Glob Patterns**: [Minimatch Documentation](https://github.com/isaacs/minimatch)
