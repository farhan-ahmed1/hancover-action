/**
 * Comprehensive error handling system with structured result patterns
 * and graceful degradation capabilities
 */

import * as core from '@actions/core';

/**
 * Error severity levels for proper escalation
 */
export enum ErrorSeverity {
    /** Non-critical errors that can be recovered from */
    // eslint-disable-next-line no-unused-vars
    WARNING = 'warning',
    /** Errors that affect functionality but allow partial operation */
    // eslint-disable-next-line no-unused-vars
    RECOVERABLE = 'recoverable',
    /** Critical errors that require immediate attention */
    // eslint-disable-next-line no-unused-vars
    FATAL = 'fatal'
}

/**
 * Error categories for better organization and handling
 */
export enum ErrorCategory {
    // eslint-disable-next-line no-unused-vars
    PARSING = 'parsing',
    // eslint-disable-next-line no-unused-vars
    CONFIG = 'config',
    // eslint-disable-next-line no-unused-vars
    GIT_DIFF = 'git_diff',
    // eslint-disable-next-line no-unused-vars
    CHANGES_COVERAGE = 'changes_coverage',
    // eslint-disable-next-line no-unused-vars
    GIST_OPERATIONS = 'gist_operations'
}

/**
 * Context information for error tracking and debugging
 */
export interface ErrorContext {
    /** Operation being performed when error occurred */
    operation: string;
    /** File or resource being processed */
    resource?: string;
    /** Step within the operation */
    step?: string;
    /** Additional metadata */
    metadata?: Record<string, any>;
    /** Stack trace for debugging */
    stackTrace?: string;
    /** Timestamp when error occurred */
    timestamp: Date;
}

/**
 * Structured error with enhanced context and recovery information
 */
export class ProcessingError extends Error {
    public readonly severity: ErrorSeverity;
    public readonly category: ErrorCategory;
    public readonly context: ErrorContext;
    public readonly recoverable: boolean;
    public readonly retryable: boolean;

    constructor(
        message: string,
        severity: ErrorSeverity,
        category: ErrorCategory,
        context: Partial<ErrorContext> = {},
        options: {
            recoverable?: boolean;
            retryable?: boolean;
            cause?: Error;
        } = {}
    ) {
        super(message);
        this.name = 'ProcessingError';
        this.severity = severity;
        this.category = category;
        this.recoverable = options.recoverable ?? (severity !== ErrorSeverity.FATAL);
        this.retryable = options.retryable ?? false;
        
        this.context = {
            operation: 'unknown',
            timestamp: new Date(),
            ...context,
            stackTrace: options.cause?.stack || this.stack
        };

        if (options.cause) {
            this.cause = options.cause;
        }
    }

    /**
     * Create a recoverable error
     */
    static recoverable(
        message: string,
        category: ErrorCategory,
        context: Partial<ErrorContext> = {},
        cause?: Error
    ): ProcessingError {
        return new ProcessingError(
            message,
            ErrorSeverity.RECOVERABLE,
            category,
            context,
            { recoverable: true, cause }
        );
    }

    /**
     * Create a fatal error
     */
    static fatal(
        message: string,
        category: ErrorCategory,
        context: Partial<ErrorContext> = {},
        cause?: Error
    ): ProcessingError {
        return new ProcessingError(
            message,
            ErrorSeverity.FATAL,
            category,
            context,
            { recoverable: false, cause }
        );
    }

    /**
     * Create a warning-level error
     */
    static warning(
        message: string,
        category: ErrorCategory,
        context: Partial<ErrorContext> = {},
        cause?: Error
    ): ProcessingError {
        return new ProcessingError(
            message,
            ErrorSeverity.WARNING,
            category,
            context,
            { recoverable: true, cause }
        );
    }

    /**
     * Get a formatted error message for logging
     */
    toLogMessage(): string {
        const parts = [
            `[${this.severity.toUpperCase()}]`,
            `[${this.category}]`,
            this.context.operation
        ];

        if (this.context.resource) {
            parts.push(`(${this.context.resource})`);
        }

        if (this.context.step) {
            parts.push(`- ${this.context.step}`);
        }

        parts.push(`: ${this.message}`);

        return parts.join(' ');
    }
}

/**
 * Warning information for non-critical issues
 */
export interface ProcessingWarning {
    message: string;
    category: ErrorCategory;
    context: ErrorContext;
    timestamp: Date;
}

/**
 * Result pattern for operations that can fail or succeed with warnings
 */
export class ProcessingResult<T = any> {
    public readonly success: boolean;
    public readonly data?: T;
    public readonly errors: ProcessingError[];
    public readonly warnings: ProcessingWarning[];

    constructor(
        success: boolean,
        data?: T,
        errors: ProcessingError[] = [],
        warnings: ProcessingWarning[] = []
    ) {
        this.success = success;
        this.data = data;
        this.errors = errors;
        this.warnings = warnings;
    }

    /**
     * Create a successful result
     */
    static success<T>(data: T): ProcessingResult<T> {
        return new ProcessingResult(true, data);
    }

    /**
     * Create a failed result
     */
    static failure<T>(error: ProcessingError): ProcessingResult<T> {
        return new ProcessingResult<T>(false, undefined, [error]);
    }

    /**
     * Create a partially successful result with warnings
     */
    static partial<T>(data: T, warnings: ProcessingWarning[]): ProcessingResult<T> {
        return new ProcessingResult(true, data, [], warnings);
    }

    /**
     * Create a result with both data and recoverable errors
     */
    static withErrors<T>(
        data: T | undefined,
        errors: ProcessingError[],
        warnings: ProcessingWarning[] = []
    ): ProcessingResult<T> {
        const hasRecoverableErrors = errors.some(e => e.recoverable);
        const hasFatalErrors = errors.some(e => !e.recoverable);
        
        return new ProcessingResult(
            hasRecoverableErrors && !hasFatalErrors && data !== undefined,
            data,
            errors,
            warnings
        );
    }

    /**
     * Check if result has any errors
     */
    hasErrors(): boolean {
        return this.errors.length > 0;
    }

    /**
     * Check if result has fatal errors
     */
    hasFatalErrors(): boolean {
        return this.errors.some(e => !e.recoverable);
    }

    /**
     * Check if result has recoverable errors only
     */
    hasRecoverableErrorsOnly(): boolean {
        return this.hasErrors() && !this.hasFatalErrors();
    }

    /**
     * Get all error messages
     */
    getErrorMessages(): string[] {
        return this.errors.map(e => e.message);
    }

    /**
     * Get all warning messages
     */
    getWarningMessages(): string[] {
        return this.warnings.map(w => w.message);
    }

    /**
     * Combine with another result
     */
    combine<U>(other: ProcessingResult<U>): ProcessingResult<T | U> {
        const combinedErrors = [...this.errors, ...other.errors];
        const combinedWarnings = [...this.warnings, ...other.warnings];
        
        // Success if both are successful
        const success = this.success && other.success;
        
        // Use first successful data, or undefined if none
        const data: T | U | undefined = this.success ? this.data : (other.success ? other.data : undefined);
        
        return new ProcessingResult<T | U>(success, data, combinedErrors, combinedWarnings);
    }
}

/**
 * Circuit breaker for preventing cascading failures
 */
export class CircuitBreaker {
    private failureCount = 0;
    private lastFailureTime?: Date;
    private readonly failureThreshold: number;
    private readonly timeoutMs: number;
    private readonly name: string;

    constructor(
        name: string,
        failureThreshold: number = 3,
        timeoutMs: number = 60000 // 1 minute
    ) {
        this.name = name;
        this.failureThreshold = failureThreshold;
        this.timeoutMs = timeoutMs;
    }

    /**
     * Check if circuit breaker should prevent execution
     */
    shouldBlock(): boolean {
        if (this.failureCount < this.failureThreshold) {
            return false;
        }

        if (!this.lastFailureTime) {
            return true;
        }

        const timeSinceLastFailure = Date.now() - this.lastFailureTime.getTime();
        
        // Reset if timeout period has passed
        if (timeSinceLastFailure > this.timeoutMs) {
            this.reset();
            return false;
        }

        return true;
    }

    /**
     * Record a failure
     */
    recordFailure(): void {
        this.failureCount++;
        this.lastFailureTime = new Date();
        
        if (this.failureCount >= this.failureThreshold) {
            core.warning(
                `Circuit breaker '${this.name}' opened after ${this.failureCount} failures. ` +
                `Will retry after ${this.timeoutMs}ms`
            );
        }
    }

    /**
     * Record a success
     */
    recordSuccess(): void {
        if (this.failureCount > 0) {
            core.info(`Circuit breaker '${this.name}' reset after successful operation`);
            this.reset();
        }
    }

    /**
     * Reset the circuit breaker
     */
    reset(): void {
        this.failureCount = 0;
        this.lastFailureTime = undefined;
    }

    /**
     * Get current state for debugging
     */
    getState(): {
        name: string;
        failureCount: number;
        isOpen: boolean;
        lastFailureTime?: Date;
        } {
        return {
            name: this.name,
            failureCount: this.failureCount,
            isOpen: this.shouldBlock(),
            lastFailureTime: this.lastFailureTime
        };
    }
}

/**
 * Error aggregator for collecting and analyzing errors across operations
 */
export class ErrorAggregator {
    private errors: ProcessingError[] = [];
    private warnings: ProcessingWarning[] = [];
    private circuitBreakers = new Map<string, CircuitBreaker>();

    /**
     * Add an error to the aggregator
     */
    addError(error: ProcessingError): void {
        this.errors.push(error);
        
        // Update circuit breaker for this category
        const breakerKey = `${error.category}-${error.context.operation}`;
        if (!this.circuitBreakers.has(breakerKey)) {
            this.circuitBreakers.set(
                breakerKey,
                new CircuitBreaker(breakerKey, 3, 60000)
            );
        }
        
        this.circuitBreakers.get(breakerKey)!.recordFailure();
    }

    /**
     * Add a warning to the aggregator
     */
    addWarning(warning: ProcessingWarning): void {
        this.warnings.push(warning);
    }

    /**
     * Record a successful operation
     */
    recordSuccess(category: ErrorCategory, operation: string): void {
        const breakerKey = `${category}-${operation}`;
        const breaker = this.circuitBreakers.get(breakerKey);
        if (breaker) {
            breaker.recordSuccess();
        }
    }

    /**
     * Check if operation should be blocked by circuit breaker
     */
    shouldBlock(category: ErrorCategory, operation: string): boolean {
        const breakerKey = `${category}-${operation}`;
        const breaker = this.circuitBreakers.get(breakerKey);
        return breaker ? breaker.shouldBlock() : false;
    }

    /**
     * Get all errors
     */
    getErrors(): ProcessingError[] {
        return [...this.errors];
    }

    /**
     * Get all warnings
     */
    getWarnings(): ProcessingWarning[] {
        return [...this.warnings];
    }

    /**
     * Get errors by category
     */
    getErrorsByCategory(category: ErrorCategory): ProcessingError[] {
        return this.errors.filter(e => e.category === category);
    }

    /**
     * Get error summary for logging
     */
    getSummary(): {
        totalErrors: number;
        fatalErrors: number;
        recoverableErrors: number;
        warnings: number;
        categorySummary: Record<string, number>;
        } {
        const categorySummary: Record<string, number> = {};
        
        for (const error of this.errors) {
            categorySummary[error.category] = (categorySummary[error.category] || 0) + 1;
        }

        return {
            totalErrors: this.errors.length,
            fatalErrors: this.errors.filter(e => !e.recoverable).length,
            recoverableErrors: this.errors.filter(e => e.recoverable).length,
            warnings: this.warnings.length,
            categorySummary
        };
    }

    /**
     * Log summary of all errors and warnings
     */
    logSummary(): void {
        const summary = this.getSummary();
        
        if (summary.totalErrors === 0 && summary.warnings === 0) {
            return;
        }

        core.info(
            `Processing Summary: ${summary.totalErrors} errors ` +
            `(${summary.fatalErrors} fatal, ${summary.recoverableErrors} recoverable), ` +
            `${summary.warnings} warnings`
        );

        if (summary.totalErrors > 0) {
            core.info(`Errors by category: ${JSON.stringify(summary.categorySummary, null, 2)}`);
        }

        // Log individual errors for debugging
        for (const error of this.errors) {
            if (error.severity === ErrorSeverity.FATAL) {
                core.error(error.toLogMessage());
            } else {
                core.warning(error.toLogMessage());
            }
        }

        // Log warnings
        for (const warning of this.warnings) {
            core.warning(`[WARNING] [${warning.category}] ${warning.context.operation}: ${warning.message}`);
        }
    }

    /**
     * Clear all errors and warnings
     */
    clear(): void {
        this.errors = [];
        this.warnings = [];
    }
}

/**
 * Utility functions for error handling
 */
export class ErrorHandlingUtils {
    /**
     * Wrap an async operation with error handling
     */
    static async withErrorHandling<T>(
        operation: () => Promise<T>,
        context: Partial<ErrorContext>,
        category: ErrorCategory,
        options: {
            retryCount?: number;
            strict?: boolean;
            fallback?: T;
        } = {}
    ): Promise<ProcessingResult<T>> {
        const { retryCount = 0, strict = false, fallback } = options;
        let lastError: ProcessingError | undefined;

        for (let attempt = 0; attempt <= retryCount; attempt++) {
            try {
                const result = await operation();
                return ProcessingResult.success(result);
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                
                lastError = new ProcessingError(
                    `${errorMessage}${attempt > 0 ? ` (attempt ${attempt + 1}/${retryCount + 1})` : ''}`,
                    strict ? ErrorSeverity.FATAL : ErrorSeverity.RECOVERABLE,
                    category,
                    {
                        ...context,
                        metadata: { attempt: attempt + 1, maxAttempts: retryCount + 1 }
                    },
                    { retryable: attempt < retryCount, cause: error instanceof Error ? error : undefined }
                );

                // If this isn't the last attempt, continue retrying
                if (attempt < retryCount) {
                    core.warning(`Retry ${attempt + 1}/${retryCount} for ${context.operation}: ${errorMessage}`);
                    continue;
                }
            }
        }

        // All retries failed
        if (lastError) {
            if (fallback !== undefined && !strict) {
                const warning: ProcessingWarning = {
                    message: `Using fallback value after ${retryCount + 1} failed attempts: ${lastError.message}`,
                    category,
                    context: { ...lastError.context },
                    timestamp: new Date()
                };
                return ProcessingResult.partial(fallback, [warning]);
            }
            
            return ProcessingResult.failure(lastError);
        }

        // This should never happen, but just in case
        return ProcessingResult.failure(
            ProcessingError.fatal('Unknown error occurred', category, context)
        );
    }

    /**
     * Create error context for a given operation
     */
    static createContext(
        operation: string,
        resource?: string,
        step?: string,
        metadata?: Record<string, any>
    ): ErrorContext {
        return {
            operation,
            resource,
            step,
            metadata,
            timestamp: new Date()
        };
    }
}
