import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    ProcessingError,
    ProcessingResult,
    ProcessingWarning,
    ErrorSeverity,
    ErrorCategory,
    ErrorAggregator,
    CircuitBreaker,
    ErrorHandlingUtils
} from '../src/infrastructure/error-handling.js';

describe('Error Handling System', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('ProcessingError', () => {
        it('should create a recoverable error correctly', () => {
            const error = ProcessingError.recoverable(
                'Test recoverable error',
                ErrorCategory.PARSING,
                { operation: 'test-op', resource: 'test-file.txt' }
            );

            expect(error.message).toBe('Test recoverable error');
            expect(error.severity).toBe(ErrorSeverity.RECOVERABLE);
            expect(error.category).toBe(ErrorCategory.PARSING);
            expect(error.recoverable).toBe(true);
            expect(error.context.operation).toBe('test-op');
            expect(error.context.resource).toBe('test-file.txt');
        });

        it('should create a fatal error correctly', () => {
            const error = ProcessingError.fatal(
                'Test fatal error',
                ErrorCategory.CONFIG,
                { operation: 'config-load' }
            );

            expect(error.message).toBe('Test fatal error');
            expect(error.severity).toBe(ErrorSeverity.FATAL);
            expect(error.category).toBe(ErrorCategory.CONFIG);
            expect(error.recoverable).toBe(false);
        });

        it('should create a warning error correctly', () => {
            const error = ProcessingError.warning(
                'Test warning',
                ErrorCategory.GIT_DIFF,
                { operation: 'git-diff' }
            );

            expect(error.message).toBe('Test warning');
            expect(error.severity).toBe(ErrorSeverity.WARNING);
            expect(error.category).toBe(ErrorCategory.GIT_DIFF);
            expect(error.recoverable).toBe(true);
        });

        it('should format log message correctly', () => {
            const error = ProcessingError.recoverable(
                'Test error message',
                ErrorCategory.PARSING,
                {
                    operation: 'parseFile',
                    resource: 'coverage.xml',
                    step: 'xml-parsing'
                }
            );

            const logMessage = error.toLogMessage();
            expect(logMessage).toContain('[RECOVERABLE]');
            expect(logMessage).toContain('[parsing]');
            expect(logMessage).toContain('parseFile');
            expect(logMessage).toContain('(coverage.xml)');
            expect(logMessage).toContain('- xml-parsing');
            expect(logMessage).toContain('Test error message');
        });
    });

    describe('ProcessingResult', () => {
        it('should create successful result', () => {
            const data = { test: 'data' };
            const result = ProcessingResult.success(data);

            expect(result.success).toBe(true);
            expect(result.data).toBe(data);
            expect(result.errors).toHaveLength(0);
            expect(result.warnings).toHaveLength(0);
        });

        it('should create failed result', () => {
            const error = ProcessingError.fatal('Test error', ErrorCategory.PARSING);
            const result = ProcessingResult.failure(error);

            expect(result.success).toBe(false);
            expect(result.data).toBeUndefined();
            expect(result.errors).toHaveLength(1);
            expect(result.errors[0]).toBe(error);
        });

        it('should create partial result with warnings', () => {
            const data = { partial: 'data' };
            const warning: ProcessingWarning = {
                message: 'Test warning',
                category: ErrorCategory.CONFIG,
                context: { operation: 'test', timestamp: new Date() },
                timestamp: new Date()
            };
            const result = ProcessingResult.partial(data, [warning]);

            expect(result.success).toBe(true);
            expect(result.data).toBe(data);
            expect(result.warnings).toHaveLength(1);
            expect(result.warnings[0]).toBe(warning);
        });

        it('should detect fatal errors correctly', () => {
            const fatalError = ProcessingError.fatal('Fatal', ErrorCategory.PARSING);
            const recoverableError = ProcessingError.recoverable('Recoverable', ErrorCategory.CONFIG);
            
            const result = ProcessingResult.withErrors(undefined, [fatalError, recoverableError]);

            expect(result.hasFatalErrors()).toBe(true);
            expect(result.hasRecoverableErrorsOnly()).toBe(false);
        });

        it('should detect recoverable errors only', () => {
            const recoverableError1 = ProcessingError.recoverable('Error 1', ErrorCategory.PARSING);
            const recoverableError2 = ProcessingError.recoverable('Error 2', ErrorCategory.CONFIG);
            
            const result = ProcessingResult.withErrors({ data: 'test' }, [recoverableError1, recoverableError2]);

            expect(result.hasFatalErrors()).toBe(false);
            expect(result.hasRecoverableErrorsOnly()).toBe(true);
            expect(result.success).toBe(true); // Should be successful with recoverable errors
        });

        it('should combine results correctly', () => {
            const result1 = ProcessingResult.success({ data1: 'test1' });
            const error = ProcessingError.recoverable('Test error', ErrorCategory.PARSING);
            const result2 = ProcessingResult.failure(error);

            const combined = result1.combine(result2);

            expect(combined.success).toBe(false); // One failed, so combined fails
            expect(combined.data).toBe(result1.data); // Uses first successful data
            expect(combined.errors).toHaveLength(1);
            expect(combined.errors[0]).toBe(error);
        });
    });

    describe('CircuitBreaker', () => {
        let circuitBreaker: CircuitBreaker;

        beforeEach(() => {
            circuitBreaker = new CircuitBreaker('test-breaker', 2, 1000); // 2 failures, 1 second timeout
        });

        it('should allow operations initially', () => {
            expect(circuitBreaker.shouldBlock()).toBe(false);
        });

        it('should block after threshold failures', () => {
            circuitBreaker.recordFailure();
            expect(circuitBreaker.shouldBlock()).toBe(false);

            circuitBreaker.recordFailure();
            expect(circuitBreaker.shouldBlock()).toBe(true);
        });

        it('should reset after successful operation', () => {
            circuitBreaker.recordFailure();
            circuitBreaker.recordFailure();
            expect(circuitBreaker.shouldBlock()).toBe(true);

            circuitBreaker.recordSuccess();
            expect(circuitBreaker.shouldBlock()).toBe(false);
        });

        it('should provide correct state information', () => {
            circuitBreaker.recordFailure();
            const state = circuitBreaker.getState();

            expect(state.name).toBe('test-breaker');
            expect(state.failureCount).toBe(1);
            expect(state.isOpen).toBe(false);
            expect(state.lastFailureTime).toBeInstanceOf(Date);
        });
    });

    describe('ErrorAggregator', () => {
        let aggregator: ErrorAggregator;

        beforeEach(() => {
            aggregator = new ErrorAggregator();
        });

        it('should collect errors and warnings', () => {
            const error = ProcessingError.recoverable('Test error', ErrorCategory.PARSING, { operation: 'test' });
            const warning: ProcessingWarning = {
                message: 'Test warning',
                category: ErrorCategory.CONFIG,
                context: { operation: 'test', timestamp: new Date() },
                timestamp: new Date()
            };

            aggregator.addError(error);
            aggregator.addWarning(warning);

            expect(aggregator.getErrors()).toHaveLength(1);
            expect(aggregator.getWarnings()).toHaveLength(1);
        });

        it('should filter errors by category', () => {
            const parseError = ProcessingError.recoverable('Parse error', ErrorCategory.PARSING, { operation: 'test' });
            const configError = ProcessingError.recoverable('Config error', ErrorCategory.CONFIG, { operation: 'test' });

            aggregator.addError(parseError);
            aggregator.addError(configError);

            const parseErrors = aggregator.getErrorsByCategory(ErrorCategory.PARSING);
            expect(parseErrors).toHaveLength(1);
            expect(parseErrors[0]).toBe(parseError);
        });

        it('should provide correct summary', () => {
            const fatalError = ProcessingError.fatal('Fatal', ErrorCategory.PARSING, { operation: 'test' });
            const recoverableError = ProcessingError.recoverable('Recoverable', ErrorCategory.CONFIG, { operation: 'test' });
            const warning: ProcessingWarning = {
                message: 'Warning',
                category: ErrorCategory.GIT_DIFF,
                context: { operation: 'test', timestamp: new Date() },
                timestamp: new Date()
            };

            aggregator.addError(fatalError);
            aggregator.addError(recoverableError);
            aggregator.addWarning(warning);

            const summary = aggregator.getSummary();
            expect(summary.totalErrors).toBe(2);
            expect(summary.fatalErrors).toBe(1);
            expect(summary.recoverableErrors).toBe(1);
            expect(summary.warnings).toBe(1);
            expect(summary.categorySummary.parsing).toBe(1);
            expect(summary.categorySummary.config).toBe(1);
        });

        it('should manage circuit breakers for operations', () => {
            const error = ProcessingError.recoverable('Test error', ErrorCategory.PARSING, { operation: 'parseFile' });

            // Initially should not block
            expect(aggregator.shouldBlock(ErrorCategory.PARSING, 'parseFile')).toBe(false);

            // Add enough failures to trigger circuit breaker
            aggregator.addError(error);
            aggregator.addError(error);
            aggregator.addError(error);

            // Should now block
            expect(aggregator.shouldBlock(ErrorCategory.PARSING, 'parseFile')).toBe(true);

            // Record success should reset
            aggregator.recordSuccess(ErrorCategory.PARSING, 'parseFile');
            expect(aggregator.shouldBlock(ErrorCategory.PARSING, 'parseFile')).toBe(false);
        });
    });

    describe('ErrorHandlingUtils', () => {
        it('should wrap successful operations', async () => {
            const operation = vi.fn().mockResolvedValue('success');
            const context = { operation: 'test' };

            const result = await ErrorHandlingUtils.withErrorHandling(
                operation,
                context,
                ErrorCategory.PARSING
            );

            expect(result.success).toBe(true);
            expect(result.data).toBe('success');
            expect(operation).toHaveBeenCalledTimes(1);
        });

        it('should handle failed operations with fallback', async () => {
            const operation = vi.fn().mockRejectedValue(new Error('Test error'));
            const context = { operation: 'test' };

            const result = await ErrorHandlingUtils.withErrorHandling(
                operation,
                context,
                ErrorCategory.PARSING,
                { fallback: 'fallback-value', strict: false }
            );

            expect(result.success).toBe(true);
            expect(result.data).toBe('fallback-value');
            expect(result.warnings).toHaveLength(1);
            expect(operation).toHaveBeenCalledTimes(1);
        });

        it('should retry operations', async () => {
            const operation = vi.fn()
                .mockRejectedValueOnce(new Error('First failure'))
                .mockRejectedValueOnce(new Error('Second failure'))
                .mockResolvedValue('success');

            const context = { operation: 'test' };

            const result = await ErrorHandlingUtils.withErrorHandling(
                operation,
                context,
                ErrorCategory.PARSING,
                { retryCount: 2 }
            );

            expect(result.success).toBe(true);
            expect(result.data).toBe('success');
            expect(operation).toHaveBeenCalledTimes(3);
        });

        it('should fail in strict mode without fallback', async () => {
            const operation = vi.fn().mockRejectedValue(new Error('Test error'));
            const context = { operation: 'test' };

            const result = await ErrorHandlingUtils.withErrorHandling(
                operation,
                context,
                ErrorCategory.PARSING,
                { strict: true }
            );

            expect(result.success).toBe(false);
            expect(result.hasFatalErrors()).toBe(true);
            expect(operation).toHaveBeenCalledTimes(1);
        });

        it('should create proper error context', () => {
            const context = ErrorHandlingUtils.createContext(
                'testOperation',
                'testResource',
                'testStep',
                { key: 'value' }
            );

            expect(context.operation).toBe('testOperation');
            expect(context.resource).toBe('testResource');
            expect(context.step).toBe('testStep');
            expect(context.metadata).toEqual({ key: 'value' });
            expect(context.timestamp).toBeInstanceOf(Date);
        });
    });

    describe('Integration Tests', () => {
        it('should handle complex error scenario with aggregator', async () => {
            const aggregator = new ErrorAggregator();
            
            // Simulate multiple failing operations
            const parseError = ProcessingError.recoverable('Parse failed', ErrorCategory.PARSING, { operation: 'parse' });
            const configError = ProcessingError.warning('Config issue', ErrorCategory.CONFIG, { operation: 'config' });
            
            aggregator.addError(parseError);
            aggregator.addError(configError);
            
            // Add a warning
            const warning: ProcessingWarning = {
                message: 'Git diff unavailable',
                category: ErrorCategory.GIT_DIFF,
                context: { operation: 'git-diff', timestamp: new Date() },
                timestamp: new Date()
            };
            aggregator.addWarning(warning);
            
            const summary = aggregator.getSummary();
            expect(summary.totalErrors).toBe(2);
            expect(summary.warnings).toBe(1);
            expect(summary.fatalErrors).toBe(0);
            expect(summary.recoverableErrors).toBe(2);
        });

        it('should demonstrate graceful degradation pattern', async () => {
            // Simulate a parsing operation that fails but has a fallback
            const failingOperation = vi.fn().mockRejectedValue(new Error('Primary parsing failed'));
            
            const result = await ErrorHandlingUtils.withErrorHandling(
                failingOperation,
                { operation: 'primaryParse', resource: 'coverage.xml' },
                ErrorCategory.PARSING,
                { 
                    fallback: { files: [], totals: { lines: { covered: 0, total: 0 } } },
                    strict: false 
                }
            );
            
            // Should succeed with fallback data
            expect(result.success).toBe(true);
            expect(result.data).toEqual({ files: [], totals: { lines: { covered: 0, total: 0 } } });
            expect(result.warnings).toHaveLength(1);
            expect(result.warnings[0].message).toContain('fallback');
        });
    });
});
