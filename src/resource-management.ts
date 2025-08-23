/**
 * Resource management and disposal utilities for preventing memory leaks
 */

import * as core from '@actions/core';

/**
 * Interface for disposable resources that need cleanup
 */
export interface Disposable {
    dispose(): Promise<void> | void;
}

/**
 * Resource tracker for managing and disposing of multiple resources
 */
export class ResourceTracker implements Disposable {
    private readonly resources = new Set<Disposable>();
    private disposed = false;

    /**
     * Track a disposable resource for automatic cleanup
     */
    track<T extends Disposable>(resource: T): T {
        if (this.disposed) {
            throw new Error('Cannot track resources on a disposed tracker');
        }
        this.resources.add(resource);
        return resource;
    }

    /**
     * Remove a resource from tracking (useful if manually disposed)
     */
    untrack(resource: Disposable): void {
        this.resources.delete(resource);
    }

    /**
     * Get the current number of tracked resources
     */
    get resourceCount(): number {
        return this.resources.size;
    }

    /**
     * Check if the tracker has been disposed
     */
    get isDisposed(): boolean {
        return this.disposed;
    }

    /**
     * Dispose of all tracked resources
     */
    async dispose(): Promise<void> {
        if (this.disposed) {
            return;
        }

        this.disposed = true;
        const resources = Array.from(this.resources);
        this.resources.clear();

        // Dispose of all resources in parallel, collecting errors
        const results = await Promise.allSettled(
            resources.map(async (resource) => {
                try {
                    await resource.dispose();
                } catch (error) {
                    core.warning(`Error disposing resource: ${error instanceof Error ? error.message : String(error)}`);
                    throw error;
                }
            })
        );

        // Check for any disposal failures
        const failures = results.filter((result): result is PromiseRejectedResult => 
            result.status === 'rejected'
        );

        if (failures.length > 0) {
            const errorMessages = failures.map(f => f.reason?.message || String(f.reason));
            core.warning(`Failed to dispose ${failures.length}/${resources.length} resources: ${errorMessages.join(', ')}`);
        } else {
            core.debug(`Successfully disposed ${resources.length} resources`);
        }
    }
}

/**
 * Disposable wrapper for Node.js timers
 */
export class DisposableTimeout implements Disposable {
    private timeoutId?: NodeJS.Timeout;
    private disposed = false;

    constructor(
        private readonly callback: () => void,
        private readonly timeoutMs: number
    ) {}

    /**
     * Start the timeout
     */
    start(): void {
        if (this.disposed) {
            throw new Error('Cannot start a disposed timeout');
        }
        
        if (this.timeoutId) {
            throw new Error('Timeout is already started');
        }

        this.timeoutId = setTimeout(() => {
            this.timeoutId = undefined;
            if (!this.disposed) {
                this.callback();
            }
        }, this.timeoutMs);
    }

    /**
     * Check if the timeout is currently active
     */
    get isActive(): boolean {
        return !this.disposed && this.timeoutId !== undefined;
    }

    /**
     * Dispose of the timeout, clearing it if active
     */
    dispose(): void {
        if (this.disposed) {
            return;
        }

        this.disposed = true;
        if (this.timeoutId) {
            clearTimeout(this.timeoutId);
            this.timeoutId = undefined;
        }
    }
}

/**
 * Disposable wrapper for Node.js intervals
 */
export class DisposableInterval implements Disposable {
    private intervalId?: NodeJS.Timeout;
    private disposed = false;

    constructor(
        private readonly callback: () => void,
        private readonly intervalMs: number
    ) {}

    /**
     * Start the interval
     */
    start(): void {
        if (this.disposed) {
            throw new Error('Cannot start a disposed interval');
        }
        
        if (this.intervalId) {
            throw new Error('Interval is already started');
        }

        this.intervalId = setInterval(() => {
            if (!this.disposed) {
                this.callback();
            }
        }, this.intervalMs);
    }

    /**
     * Check if the interval is currently active
     */
    get isActive(): boolean {
        return !this.disposed && this.intervalId !== undefined;
    }

    /**
     * Dispose of the interval, clearing it if active
     */
    dispose(): void {
        if (this.disposed) {
            return;
        }

        this.disposed = true;
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = undefined;
        }
    }
}

/**
 * Utility function for running operations with automatic resource cleanup
 */
export async function withResourceTracking<T>(
    operation: (tracker: ResourceTracker) => Promise<T>
): Promise<T> {
    const tracker = new ResourceTracker();
    try {
        return await operation(tracker);
    } finally {
        await tracker.dispose();
    }
}

/**
 * Helper for creating a disposable timeout that's automatically tracked
 */
export function createTrackedTimeout(
    tracker: ResourceTracker,
    callback: () => void,
    timeoutMs: number
): DisposableTimeout {
    const timeout = new DisposableTimeout(callback, timeoutMs);
    return tracker.track(timeout);
}

/**
 * Helper for creating a disposable interval that's automatically tracked
 */
export function createTrackedInterval(
    tracker: ResourceTracker,
    callback: () => void,
    intervalMs: number
): DisposableInterval {
    const interval = new DisposableInterval(callback, intervalMs);
    return tracker.track(interval);
}

/**
 * Resource-aware promise wrapper that ensures cleanup even on timeout/cancellation
 */
export class ResourceAwarePromise<T> implements Disposable {
    private disposed = false;
    private readonly cleanup: () => Promise<void> | void;

    constructor(
        public readonly promise: Promise<T>,
        cleanup: () => Promise<void> | void
    ) {
        this.cleanup = cleanup;
    }

    /**
     * Dispose of associated resources
     */
    async dispose(): Promise<void> {
        if (this.disposed) {
            return;
        }

        this.disposed = true;
        try {
            await this.cleanup();
        } catch (error) {
            core.warning(`Error during resource cleanup: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Wait for the promise result, automatically disposing afterwards
     */
    async wait(): Promise<T> {
        try {
            return await this.promise;
        } finally {
            await this.dispose();
        }
    }
}
