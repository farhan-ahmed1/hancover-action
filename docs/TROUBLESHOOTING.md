# Troubleshooting Guide

Common issues and solutions when using HanCover Action.

## Coverage File Issues

### Action can't find coverage files
```
Error: No coverage files found matching pattern: coverage/lcov.info
```

**Solutions:**
- Verify coverage is generated: Check your test command produces files
- Check file path: Use absolute paths from repository root
- Use glob patterns: `coverage/**/*.xml` for multiple files

### Coverage file too large
```
Error: File size exceeds 50MB limit
```

**Solutions:**
- Filter coverage to essential files only
- Split coverage into multiple files
- Use coverage exclusions in your test tool

### Invalid coverage format
```
Error: Unable to parse coverage file
```

**Solutions:**
- Verify file format matches tool output (LCOV, Cobertura, JaCoCo, Clover)
- Check file isn't empty or corrupted
- Ensure coverage tool completed successfully

## GitHub Integration Issues

### Permission denied
```
Error: Resource not accessible by integration
```

**Solutions:**
- Add `pull-requests: write` permission to workflow
- Add `contents: read` permission for checkout

### Gist integration failing
```
Error: Failed to update coverage gist
```

**Solutions:**
- Verify `COVERAGE_GIST_ID` secret is set correctly
- Ensure `GIST_TOKEN` has `gist` scope
- Check gist exists and is public

## Configuration Issues

### Package grouping not working
```
Warning: Pattern "src/**" matches no files
```

**Solutions:**
- Check patterns match actual file paths in coverage
- Use correct glob syntax (`**` for recursive matching)
- Test patterns against your actual directory structure

### Thresholds not applied
```
Coverage shows as passing but should fail
```

**Solutions:**
- Check `min-threshold` is set correctly
- Verify threshold applies to overall coverage
- Use `thresholds` input for package-specific limits

## Performance Issues

### Action timeout
```
Error: The operation was canceled
```

**Solutions:**
- Reduce coverage file size
- Filter coverage to essential files only
- Check for very large XML files

### Slow performance
- Large coverage files take longer to process
- Multiple files are processed efficiently
- Consider splitting very large monorepos

## Getting Help

Still having issues?

1. **Enable debug logging**: Set `ACTIONS_STEP_DEBUG=true` in repository secrets
2. **Check examples**: Review [examples/workflows.yml](../examples/workflows.yml)
3. **Open an issue**: [GitHub Issues](https://github.com/farhan-ahmed1/hancover-action/issues)

Include in your issue:
- Workflow file
- Coverage file format and size
- Error message
- Debug logs (if available)
