/**
 * Timeout utilities for enforcing time limits on operations
 */

import * as core from '@actions/core';

export interface TimeoutOptions {
    timeoutMs: number;
    operation: string;
    onTimeout?: () => void;
}

/**
 * Create a timeout promise that rejects after the specified duration
 */
export function createTimeoutPromise(timeoutMs: number, operation: string): Promise<never> {
    return new Promise((_, reject) => {
        setTimeout(() => {
            reject(new Error(`Operation '${operation}' timed out after ${timeoutMs}ms`));
        }, timeoutMs);
    });
}

/**
 * Race a promise against a timeout
 */
export async function withTimeout<T>(
    promise: Promise<T>,
    options: TimeoutOptions
): Promise<T> {
    const { timeoutMs, operation, onTimeout } = options;
    
    if (timeoutMs <= 0) {
        // No timeout - return promise directly
        return promise;
    }

    const timeoutPromise = createTimeoutPromise(timeoutMs, operation);
    
    try {
        return await Promise.race([promise, timeoutPromise]);
    } catch (error) {
        if (onTimeout && error instanceof Error && error.message.includes('timed out')) {
            onTimeout();
        }
        throw error;
    }
}

/**
 * Create a timeout controller for manual timeout management
 */
export class TimeoutController {
    private timeoutId?: NodeJS.Timeout;
    private readonly timeoutMs: number;
    private readonly operation: string;
    private isActive = false;

    constructor(timeoutMs: number, operation: string) {
        this.timeoutMs = timeoutMs;
        this.operation = operation;
    }

    start(): Promise<never> {
        if (this.isActive) {
            throw new Error('Timeout controller is already active');
        }

        this.isActive = true;
        
        return new Promise((_, reject) => {
            if (this.timeoutMs <= 0) {
                // No timeout
                return;
            }

            this.timeoutId = setTimeout(() => {
                this.isActive = false;
                core.warning(`Operation '${this.operation}' exceeded timeout of ${this.timeoutMs}ms`);
                reject(new Error(`Operation '${this.operation}' timed out after ${this.timeoutMs}ms`));
            }, this.timeoutMs);
        });
    }

    clear(): void {
        if (this.timeoutId) {
            clearTimeout(this.timeoutId);
            this.timeoutId = undefined;
        }
        this.isActive = false;
    }

    isRunning(): boolean {
        return this.isActive;
    }

    extend(additionalMs: number): void {
        if (!this.isActive) {
            throw new Error('Cannot extend inactive timeout controller');
        }

        this.clear();
        this.isActive = true; // Reactivate after clearing
        const newTimeout = this.timeoutMs + additionalMs;
        
        this.timeoutId = setTimeout(() => {
            this.isActive = false;
            core.warning(`Operation '${this.operation}' exceeded extended timeout of ${newTimeout}ms`);
        }, newTimeout);
    }
}

/**
 * Timeout manager for file operations
 */
export class FileOperationTimeout {
    private readonly baseTimeoutMs: number;
    private readonly perMBTimeoutMs: number;

    constructor(baseTimeoutMs = 30000, perMBTimeoutMs = 5000) {
        this.baseTimeoutMs = baseTimeoutMs;
        this.perMBTimeoutMs = perMBTimeoutMs;
    }

    /**
     * Calculate timeout based on file size
     */
    calculateTimeout(fileSizeBytes: number): number {
        const fileSizeMB = fileSizeBytes / (1024 * 1024);
        const calculatedTimeout = this.baseTimeoutMs + (fileSizeMB * this.perMBTimeoutMs);
        
        // Cap at reasonable maximum (10 minutes)
        const maxTimeout = 10 * 60 * 1000;
        return Math.min(calculatedTimeout, maxTimeout);
    }

    /**
     * Create timeout options for a file operation
     */
    createOptions(filePath: string, fileSizeBytes: number): TimeoutOptions {
        const timeoutMs = this.calculateTimeout(fileSizeBytes);
        const fileSizeMB = (fileSizeBytes / (1024 * 1024)).toFixed(2);
        
        return {
            timeoutMs,
            operation: `Processing file ${filePath} (${fileSizeMB}MB)`,
            onTimeout: () => {
                core.warning(`File processing timeout: ${filePath} (${fileSizeMB}MB) exceeded ${timeoutMs}ms limit`);
            }
        };
    }
}

/**
 * Global timeout manager instance
 */
export const globalTimeoutManager = new FileOperationTimeout();

/**
 * Apply timeout to file reading operations
 */
export async function withFileTimeout<T>(
    operation: Promise<T>,
    filePath: string,
    fileSizeBytes: number,
    customTimeoutMs?: number
): Promise<T> {
    const timeoutMs = customTimeoutMs ?? globalTimeoutManager.calculateTimeout(fileSizeBytes);
    const options: TimeoutOptions = {
        timeoutMs,
        operation: `File operation on ${filePath}`,
        onTimeout: () => {
            const sizeMB = (fileSizeBytes / (1024 * 1024)).toFixed(1);
            core.warning(`File operation timed out: ${filePath} (${sizeMB}MB) after ${timeoutMs}ms`);
        }
    };

    return withTimeout(operation, options);
}

/**
 * Batch timeout for multiple operations
 */
export async function withBatchTimeout<T>(
    operations: Array<() => Promise<T>>,
    totalTimeoutMs: number,
    batchName: string
): Promise<T[]> {
    const controller = new TimeoutController(totalTimeoutMs, `Batch operation: ${batchName}`);
    const timeoutPromise = controller.start();
    
    try {
        const results = await Promise.race([
            Promise.all(operations.map(op => op())),
            timeoutPromise
        ]);
        
        controller.clear();
        return results as T[];
    } catch (error) {
        controller.clear();
        throw error;
    }
}
