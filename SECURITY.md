# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in HanCover Action, please report it privately to maintain security.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please send an email to security@farhanlabs.com with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

We will respond within 48 hours and work with you to address the issue promptly.

## Security Measures

HanCover Action implements several security best practices:

- **File size limits**: 50MB per file, 200MB total (configurable)
- **Safe XML parsing**: DTD and XInclude disabled
- **Minimal permissions**: Only requires `pull-requests: write` and `contents: read`
- **Input validation**: All inputs are validated and sanitized
- **Timeout protection**: Configurable execution timeout (default 120s)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅         |

## Security Best Practices for Users

When using HanCover Action:

1. Use the minimal required permissions:
   ```yaml
   permissions:
     pull-requests: write
     contents: read
   ```

2. Pin to specific versions:
   ```yaml
   uses: farhan-ahmed/hancover-action@v0.1.0  # Not @main
   ```

3. Review coverage file sources to ensure they come from trusted build processes

4. Consider setting strict mode for production environments:
   ```yaml
   with:
     strict: true
   ```
