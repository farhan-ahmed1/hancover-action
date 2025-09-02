import * as core from '@actions/core';
import { randomUUID } from 'crypto';

export interface LogContext {
    correlationId: string;
    operation: string;
    startTime: number;
    memoryUsage?: NodeJS.MemoryUsage;
    metadata?: Record<string, any>;
}

export interface LogEntry {
    timestamp: string;
    level: 'debug' | 'info' | 'warning' | 'error';
    message: string;
    correlationId: string;
    operation: string;
    duration?: number;
    memoryUsage?: NodeJS.MemoryUsage;
    metadata?: Record<string, any>;
}

class StructuredLogger {
    private correlationId: string;
    
    constructor(correlationId?: string) {
        this.correlationId = correlationId || randomUUID();
    }

    createContext(operation: string, metadata?: Record<string, any>): LogContext {
        return {
            correlationId: this.correlationId,
            operation,
            startTime: Date.now(),
            memoryUsage: process.memoryUsage(),
            metadata
        };
    }

    private formatLog(entry: LogEntry): string {
        const { timestamp, level, message, correlationId, operation, duration, memoryUsage, metadata } = entry;
        
        const logObj = {
            timestamp,
            level: level.toUpperCase(),
            message,
            correlationId,
            operation,
            ...(duration && { durationMs: duration }),
            ...(memoryUsage && { 
                memoryMB: {
                    heap: Math.round(memoryUsage.heapUsed / 1024 / 1024),
                    external: Math.round(memoryUsage.external / 1024 / 1024),
                    total: Math.round(memoryUsage.rss / 1024 / 1024)
                }
            }),
            ...(metadata && { metadata })
        };

        return JSON.stringify(logObj);
    }

    debug(message: string, context: LogContext, metadata?: Record<string, any>): void {
        const entry: LogEntry = {
            timestamp: new Date().toISOString(),
            level: 'debug',
            message,
            correlationId: context.correlationId,
            operation: context.operation,
            metadata: { ...context.metadata, ...metadata }
        };
        
        core.debug(this.formatLog(entry));
    }

    info(message: string, context: LogContext, metadata?: Record<string, any>): void {
        const entry: LogEntry = {
            timestamp: new Date().toISOString(),
            level: 'info',
            message,
            correlationId: context.correlationId,
            operation: context.operation,
            duration: Date.now() - context.startTime,
            memoryUsage: process.memoryUsage(),
            metadata: { ...context.metadata, ...metadata }
        };
        
        core.info(this.formatLog(entry));
    }

    warning(message: string, context: LogContext, error?: Error, metadata?: Record<string, any>): void {
        const entry: LogEntry = {
            timestamp: new Date().toISOString(),
            level: 'warning',
            message,
            correlationId: context.correlationId,
            operation: context.operation,
            duration: Date.now() - context.startTime,
            metadata: { 
                ...context.metadata, 
                ...metadata,
                ...(error && { error: error.message, stack: error.stack })
            }
        };
        
        core.warning(this.formatLog(entry));
    }

    error(message: string, context: LogContext, error?: Error, metadata?: Record<string, any>): void {
        const entry: LogEntry = {
            timestamp: new Date().toISOString(),
            level: 'error',
            message,
            correlationId: context.correlationId,
            operation: context.operation,
            duration: Date.now() - context.startTime,
            memoryUsage: process.memoryUsage(),
            metadata: { 
                ...context.metadata, 
                ...metadata,
                ...(error && { error: error.message, stack: error.stack })
            }
        };
        
        core.error(this.formatLog(entry));
    }

    /**
     * Measure operation execution time and log results
     */
    async measureOperation<T>(
        operation: string,
        // eslint-disable-next-line no-unused-vars
        fn: (logContext: LogContext) => Promise<T>,
        metadata?: Record<string, any>
    ): Promise<T> {
        const context = this.createContext(operation, metadata);
        this.debug(`Starting operation: ${operation}`, context);
        
        try {
            const result = await fn(context);
            this.info(`Completed operation: ${operation}`, context, { success: true });
            return result;
        } catch (error) {
            this.error(`Failed operation: ${operation}`, context, error as Error);
            throw error;
        }
    }

    /**
     * Create a child logger with the same correlation ID
     */
    child(operation: string, metadata?: Record<string, any>): { logger: StructuredLogger; context: LogContext } {
        const childLogger = new StructuredLogger(this.correlationId);
        const context = childLogger.createContext(operation, metadata);
        return { logger: childLogger, context };
    }
}

// Export singleton instance
export const logger = new StructuredLogger();

// Export class for creating new instances
export { StructuredLogger };
