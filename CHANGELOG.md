# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-08-21

### Added
- Multi-format coverage support (LCOV, Cobertura, JaCoCo, Clover)
- Smart PR comments with sticky updates (no spam)
- Dynamic coverage badges via GitHub Gists
- Intelligent package grouping with customizable configuration
- Change tracking with visual delta indicators
- Security-focused XML parsing with XXE protection
- Comprehensive input validation and sanitization
- File size limits (50MB per file, 200MB total)
- Timeout protection (configurable, default 120s)
- Support for both Gist-based and file-based baseline storage
- Enhanced error handling with detailed context
- Coverage threshold validation with configurable pass/fail indicators
- Ecosystem auto-detection for common project types
- Extensive test suite with 173+ test files
- Security audit capabilities with dependency scanning
- OpenSSF Scorecard integration
- CodeQL security analysis
- Dependabot integration for dependency updates

### Security
- XML bomb protection with nesting limits
- DTD and entity expansion disabled
- Path sanitization to prevent directory traversal
- Input validation using Zod schemas
- Minimal permission requirements (`pull-requests: write`, `contents: read`)
- Secure token handling for GitHub API access
- File size enforcement to prevent DoS attacks

### Documentation
- Comprehensive README with quick start guide
- Setup guide with step-by-step instructions
- API reference with complete input/output documentation
- Configuration guide for advanced package grouping
- Security policy with vulnerability reporting procedures
- Contributing guidelines
- Multiple workflow examples for different use cases

## [0.1.0] - Unreleased

### Added
- Initial release of HanCover Action
- Basic coverage parsing and PR comment generation
- Foundation for multi-format support
- Core security and validation framework
- Basic GitHub Actions workflow integration

---

## Release Notes

### Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version when making incompatible API changes
- **MINOR** version when adding functionality in a backwards compatible manner  
- **PATCH** version when making backwards compatible bug fixes

### Upcoming Releases

#### v1.0.0 (Planned)
The first stable release will include:
- Production-ready multi-format coverage parsing
- Comprehensive security measures
- Complete documentation suite
- GitHub Marketplace listing
- Performance optimizations for large files
- Extensive test coverage

#### Future Roadmap

**v1.1.0** - Enhanced Performance
- Streaming XML parser for large files
- Progress indicators for long operations
- Advanced caching mechanisms

**v1.2.0** - Advanced Features  
- HTML report generation
- Multiple baseline comparison
- Advanced package grouping rules
- Enhanced ecosystem integration

**v2.0.0** - Major Enhancements
- Breaking changes will be clearly documented
- New architecture improvements
- Enhanced user experience features

### Breaking Changes Policy

- Breaking changes will only be introduced in major versions
- All breaking changes will be documented with migration guides
- Deprecated features will be supported for at least one major version
- Users will receive advance notice of planned breaking changes

### Support Policy

- **Current major version**: Full support with security updates and bug fixes
- **Previous major version**: Security updates only for 6 months after new major release
- **Older versions**: No support, users encouraged to upgrade

### Contributing to Changelog

When contributing to this project:

1. Add your changes to the `[Unreleased]` section
2. Use the appropriate category:
   - `Added` for new features
   - `Changed` for changes in existing functionality  
   - `Deprecated` for soon-to-be removed features
   - `Removed` for now removed features
   - `Fixed` for any bug fixes
   - `Security` for vulnerability fixes
3. Include PR numbers: `- New feature description (#123)`
4. Describe the impact and any migration needed for breaking changes

### Links

- [GitHub Repository](https://github.com/farhan-ahmed1/hancover-action)
- [Documentation](https://github.com/farhan-ahmed1/hancover-action/tree/main/docs)
- [Security Policy](https://github.com/farhan-ahmed1/hancover-action/blob/main/SECURITY.md)
- [Contributing Guide](https://github.com/farhan-ahmed1/hancover-action/blob/main/CONTRIBUTING.md)
