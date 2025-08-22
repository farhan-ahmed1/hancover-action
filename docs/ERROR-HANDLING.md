# Enhanced Error Handling System

This document describes the comprehensive error handling and graceful degradation system implemented in the HanCover Action project.

## Overview

The enhanced error handling system provides:

- **Structured Error Management**: Clear error categorization and severity levels
- **Circuit Breaker Pattern**: Prevents cascading failures and resource waste
- **Result Pattern**: Consistent return values with success/failure states
- **Graceful Degradation**: Fallback mechanisms to keep the system operational
- **Comprehensive Logging**: Detailed error context and aggregated summaries

## Core Components

### 1. ProcessingError

A structured error class that provides enhanced context and categorization:

```typescript
class ProcessingError extends Error {
    severity: ErrorSeverity;     // WARNING, RECOVERABLE, FATAL
    category: ErrorCategory;     // PARSING, CONFIG, GIT_DIFF, etc.
    context: ErrorContext;       // Operation details, resource, metadata
    recoverable: boolean;        // Whether the error can be recovered from
    retryable: boolean;         // Whether the operation should be retried
}
```

**Usage Examples:**

```typescript
// Create different types of errors
const recoverableError = ProcessingError.recoverable(
    'Failed to parse coverage file',
    ErrorCategory.PARSING,
    { operation: 'parseAnyCoverage', resource: 'coverage.xml' }
);

const fatalError = ProcessingError.fatal(
    'Configuration file is corrupted',
    ErrorCategory.CONFIG,
    { operation: 'loadConfig' }
);

const warning = ProcessingError.warning(
    'Git diff unavailable, using full coverage',
    ErrorCategory.GIT_DIFF,
    { operation: 'git-diff' }
);
```

### 2. ProcessingResult

A result pattern that wraps operation outcomes:

```typescript
class ProcessingResult<T> {
    success: boolean;
    data?: T;
    errors: ProcessingError[];
    warnings: ProcessingWarning[];
}
```

**Usage Examples:**

```typescript
// Successful operation
const result = ProcessingResult.success(parsedData);

// Failed operation
const result = ProcessingResult.failure(error);

// Partial success with warnings
const result = ProcessingResult.partial(fallbackData, [warning]);

// Operation with recoverable errors
const result = ProcessingResult.withErrors(partialData, [recoverableError]);
```

### 3. CircuitBreaker

Prevents repeated failures from wasting resources:

```typescript
class CircuitBreaker {
    shouldBlock(): boolean;      // Check if operations should be blocked
    recordFailure(): void;       // Record a failure
    recordSuccess(): void;       // Record a success (resets the breaker)
    reset(): void;              // Manually reset the breaker
}
```

**Configuration:**
- Failure threshold: 3 failures before opening
- Timeout period: 60 seconds before allowing retry
- Per-operation tracking: Each operation category has its own breaker

### 4. ErrorAggregator

Centralizes error collection and provides circuit breaker management:

```typescript
class ErrorAggregator {
    addError(error: ProcessingError): void;
    addWarning(warning: ProcessingWarning): void;
    shouldBlock(category: ErrorCategory, operation: string): boolean;
    recordSuccess(category: ErrorCategory, operation: string): void;
    getSummary(): ErrorSummary;
    logSummary(): void;
}
```

## Error Categories

The system categorizes errors into logical groups:

- `PARSING`: Coverage file parsing failures
- `CONFIG`: Configuration loading and validation errors
- `GIT_DIFF`: Git operations and diff parsing failures
- `CHANGES_COVERAGE`: Changes coverage computation errors
- `BASELINE`: Baseline coverage retrieval failures
- `GIST_OPERATIONS`: GitHub Gist API interactions
- `FILE_SYSTEM`: File system access errors
- `NETWORK`: Network connectivity issues
- `VALIDATION`: Input validation failures
- `TIMEOUT`: Operation timeout errors

## Error Severity Levels

- `WARNING`: Non-critical issues that don't affect core functionality
- `RECOVERABLE`: Errors that can be worked around with fallbacks
- `FATAL`: Critical errors that require immediate attention

## Implementation Patterns

### 1. Wrapper Functions with Recovery

Each major operation is wrapped with enhanced error handling:

```typescript
async function parseWithRecovery(file: string, options: any, aggregator: ErrorAggregator): Promise<ProcessingResult<any>> {
    const context = ErrorHandlingUtils.createContext('parseAnyCoverage', file, 'coverage_parsing');
    
    // Check circuit breaker
    if (aggregator.shouldBlock(ErrorCategory.PARSING, 'parseAnyCoverage')) {
        return ProcessingResult.failure(
            ProcessingError.recoverable('Circuit breaker blocking parsing operations', ErrorCategory.PARSING, context)
        );
    }

    return ErrorHandlingUtils.withErrorHandling(
        () => parseAnyCoverage(file, options),
        context,
        ErrorCategory.PARSING,
        { retryCount: 1, strict: false }
    );
}
```

### 2. Graceful Degradation with Fallbacks

Operations provide fallback values when the primary method fails:

```typescript
// Config loading with fallback
const configResult = await loadConfigWithRecovery(aggregator);
if (configResult.success) {
    config = configResult.data;
} else {
    // Uses fallback config from the result
    config = configResult.data; // Contains safe defaults
}
```

### 3. Circuit Breaker Integration

The error aggregator automatically manages circuit breakers:

```typescript
// Recording failures automatically updates circuit breakers
parseResult.errors.forEach(e => aggregator.addError(e));

// Subsequent operations check the circuit breaker
if (aggregator.shouldBlock(ErrorCategory.PARSING, 'parseAnyCoverage')) {
    // Operation is skipped to prevent resource waste
}

// Success resets the circuit breaker
if (parseResult.success) {
    aggregator.recordSuccess(ErrorCategory.PARSING, 'parseAnyCoverage');
}
```

## Benefits

### 1. Resilient Operation

- **Circuit Breakers** prevent cascading failures
- **Retry Logic** handles transient errors
- **Fallback Mechanisms** ensure continued operation
- **Timeout Enforcement** prevents hanging operations

### 2. Better Observability

- **Structured Logging** with consistent error context
- **Error Categorization** for better incident response
- **Aggregated Summaries** for operational insights
- **Circuit Breaker State** for system health monitoring

### 3. Improved User Experience

- **Graceful Degradation** maintains functionality
- **Clear Error Messages** with actionable context
- **Partial Results** when some operations succeed
- **Non-Strict Mode** allows continued processing

### 4. Maintainable Code

- **Consistent Error Handling** patterns
- **Separation of Concerns** between business logic and error handling
- **Testable Components** with clear interfaces
- **Comprehensive Test Coverage** for error scenarios

## Error Handling Flow

1. **Operation Execution**:
   - Check circuit breaker before execution
   - Execute operation with timeout and retry logic
   - Capture detailed error context

2. **Error Processing**:
   - Categorize and classify errors
   - Update circuit breaker state
   - Apply fallback strategies if configured

3. **Result Aggregation**:
   - Collect errors and warnings
   - Provide comprehensive summaries
   - Log structured information

4. **Graceful Continuation**:
   - Use fallback data when available
   - Skip non-critical operations if blocked
   - Maintain system stability

## Configuration

### Circuit Breaker Settings

```typescript
// Default configuration
const circuitBreaker = new CircuitBreaker(
    'operation-name',
    3,      // failure threshold
    60000   // timeout in milliseconds
);
```

### Error Handling Options

```typescript
const options = {
    retryCount: 2,           // Number of retries
    strict: false,           // Fail fast vs. graceful degradation
    fallback: defaultValue,  // Fallback value for failures
    timeoutMs: 30000        // Operation timeout
};
```

## Best Practices

### 1. Error Context

Always provide meaningful context when creating errors:

```typescript
const context = ErrorHandlingUtils.createContext(
    'parseAnyCoverage',      // operation
    'coverage.xml',         // resource
    'xml-parsing',          // step
    { fileSize: 1024 }      // metadata
);
```

### 2. Appropriate Severity

Choose error severity based on impact:

- Use `WARNING` for non-blocking issues
- Use `RECOVERABLE` for errors with fallbacks
- Use `FATAL` only for unrecoverable situations

### 3. Circuit Breaker Granularity

Configure circuit breakers at appropriate granularity:

- Per operation type (e.g., parsing, network calls)
- Per resource category (e.g., gist operations)
- Avoid too fine-grained breakers

### 4. Fallback Quality

Ensure fallbacks provide reasonable functionality:

- Use safe defaults for configuration
- Provide empty but valid data structures
- Maintain type compatibility

## Testing

The error handling system includes comprehensive tests:

- **Unit Tests**: Individual component behavior
- **Integration Tests**: Cross-component error scenarios
- **Circuit Breaker Tests**: Failure threshold and recovery
- **Fallback Tests**: Graceful degradation scenarios

### Test Examples

```typescript
// Testing circuit breaker behavior
it('should respect circuit breaker', async () => {
    // Trigger circuit breaker
    for (let i = 0; i < 3; i++) {
        aggregator.addError(testError);
    }
    
    // Verify operation is blocked
    const result = await parseWithRecovery('file.xml', {}, aggregator);
    expect(result.errors[0].message).toContain('Circuit breaker blocking');
});

// Testing graceful degradation
it('should handle cascading failures gracefully', async () => {
    // Setup multiple failing operations
    mockParseAnyCoverage.mockRejectedValue(new Error('Parse failed'));
    mockLoadConfig.mockImplementation(() => { throw new Error('Config failed'); });
    
    // Verify system continues with fallbacks
    const parseResult = await parseWithRecovery('coverage.xml', {}, aggregator);
    expect(parseResult.success).toBe(false);
    
    const configResult = await loadConfigWithRecovery(aggregator);
    expect(configResult.success).toBe(true); // Uses fallback
});
```

This enhanced error handling system provides the foundation for building resilient, observable, and maintainable software that gracefully handles failures while providing valuable diagnostic information.
