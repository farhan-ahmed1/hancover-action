import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    Disposable,
    ResourceTracker,
    DisposableTimeout,
    DisposableInterval,
    withResourceTracking,
    createTrackedTimeout,
    createTrackedInterval,
    ResourceAwarePromise
} from '../src/resource-management.js';
import * as core from '@actions/core';

// Mock @actions/core
vi.mock('@actions/core', () => ({
    warning: vi.fn(),
    debug: vi.fn()
}));

describe('Resource Management', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
        vi.restoreAllMocks();
    });

    describe('ResourceTracker', () => {
        it('should track and dispose of resources', async () => {
            const tracker = new ResourceTracker();
            const mockDisposable: Disposable = {
                dispose: vi.fn()
            };

            const tracked = tracker.track(mockDisposable);
            expect(tracked).toBe(mockDisposable);
            expect(tracker.resourceCount).toBe(1);

            await tracker.dispose();
            expect(mockDisposable.dispose).toHaveBeenCalledOnce();
            expect(tracker.resourceCount).toBe(0);
            expect(tracker.isDisposed).toBe(true);
        });

        it('should handle disposal errors gracefully', async () => {
            const tracker = new ResourceTracker();
            const failingDisposable: Disposable = {
                dispose: vi.fn().mockRejectedValue(new Error('Disposal failed'))
            };
            const successfulDisposable: Disposable = {
                dispose: vi.fn()
            };

            tracker.track(failingDisposable);
            tracker.track(successfulDisposable);

            await tracker.dispose();

            expect(failingDisposable.dispose).toHaveBeenCalled();
            expect(successfulDisposable.dispose).toHaveBeenCalled();
            expect(core.warning).toHaveBeenCalledWith(
                expect.stringContaining('Failed to dispose 1/2 resources')
            );
        });

        it('should prevent tracking on disposed tracker', () => {
            const tracker = new ResourceTracker();
            tracker.dispose();

            const mockDisposable: Disposable = { dispose: vi.fn() };
            
            expect(() => tracker.track(mockDisposable)).toThrow(
                'Cannot track resources on a disposed tracker'
            );
        });

        it('should allow untracking resources', async () => {
            const tracker = new ResourceTracker();
            const mockDisposable: Disposable = { dispose: vi.fn() };

            tracker.track(mockDisposable);
            expect(tracker.resourceCount).toBe(1);

            tracker.untrack(mockDisposable);
            expect(tracker.resourceCount).toBe(0);

            await tracker.dispose();
            expect(mockDisposable.dispose).not.toHaveBeenCalled();
        });

        it('should handle multiple dispose calls safely', async () => {
            const tracker = new ResourceTracker();
            const mockDisposable: Disposable = { dispose: vi.fn() };

            tracker.track(mockDisposable);
            
            await tracker.dispose();
            await tracker.dispose(); // Second disposal should be safe

            expect(mockDisposable.dispose).toHaveBeenCalledOnce();
        });
    });

    describe('DisposableTimeout', () => {
        it('should execute callback after timeout', () => {
            const callback = vi.fn();
            const timeout = new DisposableTimeout(callback, 1000);

            timeout.start();
            expect(timeout.isActive).toBe(true);

            vi.advanceTimersByTime(1000);
            expect(callback).toHaveBeenCalledOnce();
            expect(timeout.isActive).toBe(false);
        });

        it('should be disposable before execution', () => {
            const callback = vi.fn();
            const timeout = new DisposableTimeout(callback, 1000);

            timeout.start();
            expect(timeout.isActive).toBe(true);

            timeout.dispose();
            expect(timeout.isActive).toBe(false);

            vi.advanceTimersByTime(1000);
            expect(callback).not.toHaveBeenCalled();
        });

        it('should not execute callback after disposal', () => {
            const callback = vi.fn();
            const timeout = new DisposableTimeout(callback, 1000);

            timeout.start();
            timeout.dispose();

            vi.advanceTimersByTime(1000);
            expect(callback).not.toHaveBeenCalled();
        });

        it('should prevent starting disposed timeout', () => {
            const timeout = new DisposableTimeout(vi.fn(), 1000);
            timeout.dispose();

            expect(() => timeout.start()).toThrow('Cannot start a disposed timeout');
        });

        it('should prevent double start', () => {
            const timeout = new DisposableTimeout(vi.fn(), 1000);
            timeout.start();

            expect(() => timeout.start()).toThrow('Timeout is already started');
        });

        it('should handle multiple dispose calls safely', () => {
            const timeout = new DisposableTimeout(vi.fn(), 1000);
            timeout.start();

            timeout.dispose();
            timeout.dispose(); // Should not throw

            expect(timeout.isActive).toBe(false);
        });
    });

    describe('DisposableInterval', () => {
        it('should execute callback repeatedly', () => {
            const callback = vi.fn();
            const interval = new DisposableInterval(callback, 1000);

            interval.start();
            expect(interval.isActive).toBe(true);

            vi.advanceTimersByTime(3000);
            expect(callback).toHaveBeenCalledTimes(3);
        });

        it('should be disposable during execution', () => {
            const callback = vi.fn();
            const interval = new DisposableInterval(callback, 1000);

            interval.start();
            vi.advanceTimersByTime(2000);
            expect(callback).toHaveBeenCalledTimes(2);

            interval.dispose();
            expect(interval.isActive).toBe(false);

            vi.advanceTimersByTime(2000);
            expect(callback).toHaveBeenCalledTimes(2); // No additional calls
        });

        it('should not execute callback after disposal', () => {
            const callback = vi.fn();
            const interval = new DisposableInterval(callback, 1000);

            interval.start();
            interval.dispose();

            vi.advanceTimersByTime(1000);
            expect(callback).not.toHaveBeenCalled();
        });

        it('should prevent starting disposed interval', () => {
            const interval = new DisposableInterval(vi.fn(), 1000);
            interval.dispose();

            expect(() => interval.start()).toThrow('Cannot start a disposed interval');
        });

        it('should prevent double start', () => {
            const interval = new DisposableInterval(vi.fn(), 1000);
            interval.start();

            expect(() => interval.start()).toThrow('Interval is already started');
        });
    });

    describe('withResourceTracking', () => {
        it('should automatically dispose resources on completion', async () => {
            const mockDisposable: Disposable = { dispose: vi.fn() };

            const result = await withResourceTracking(async (tracker) => {
                tracker.track(mockDisposable);
                return 'success';
            });

            expect(result).toBe('success');
            expect(mockDisposable.dispose).toHaveBeenCalledOnce();
        });

        it('should dispose resources even on error', async () => {
            const mockDisposable: Disposable = { dispose: vi.fn() };

            await expect(
                withResourceTracking(async (tracker) => {
                    tracker.track(mockDisposable);
                    throw new Error('Test error');
                })
            ).rejects.toThrow('Test error');

            expect(mockDisposable.dispose).toHaveBeenCalledOnce();
        });
    });

    describe('createTrackedTimeout', () => {
        it('should create and track timeout', () => {
            const tracker = new ResourceTracker();
            const callback = vi.fn();

            const timeout = createTrackedTimeout(tracker, callback, 1000);
            expect(tracker.resourceCount).toBe(1);

            timeout.start();
            vi.advanceTimersByTime(1000);
            expect(callback).toHaveBeenCalledOnce();
        });

        it('should dispose timeout when tracker is disposed', async () => {
            const tracker = new ResourceTracker();
            const callback = vi.fn();

            const timeout = createTrackedTimeout(tracker, callback, 1000);
            timeout.start();

            await tracker.dispose();
            
            vi.advanceTimersByTime(1000);
            expect(callback).not.toHaveBeenCalled();
        });
    });

    describe('createTrackedInterval', () => {
        it('should create and track interval', () => {
            const tracker = new ResourceTracker();
            const callback = vi.fn();

            const interval = createTrackedInterval(tracker, callback, 1000);
            expect(tracker.resourceCount).toBe(1);

            interval.start();
            vi.advanceTimersByTime(2000);
            expect(callback).toHaveBeenCalledTimes(2);
        });

        it('should dispose interval when tracker is disposed', async () => {
            const tracker = new ResourceTracker();
            const callback = vi.fn();

            const interval = createTrackedInterval(tracker, callback, 1000);
            interval.start();
            vi.advanceTimersByTime(1000);
            expect(callback).toHaveBeenCalledTimes(1);

            await tracker.dispose();
            
            vi.advanceTimersByTime(1000);
            expect(callback).toHaveBeenCalledTimes(1); // No additional calls
        });
    });

    describe('ResourceAwarePromise', () => {
        it('should execute cleanup after promise completion', async () => {
            const cleanup = vi.fn();
            const promise = Promise.resolve('success');

            const resourcePromise = new ResourceAwarePromise(promise, cleanup);
            const result = await resourcePromise.wait();

            expect(result).toBe('success');
            expect(cleanup).toHaveBeenCalledOnce();
        });

        it('should execute cleanup after promise rejection', async () => {
            const cleanup = vi.fn();
            const promise = Promise.reject(new Error('Test error'));

            const resourcePromise = new ResourceAwarePromise(promise, cleanup);
            
            await expect(resourcePromise.wait()).rejects.toThrow('Test error');
            expect(cleanup).toHaveBeenCalledOnce();
        });

        it('should handle cleanup errors gracefully', async () => {
            const cleanup = vi.fn().mockRejectedValue(new Error('Cleanup failed'));
            const promise = Promise.resolve('success');

            const resourcePromise = new ResourceAwarePromise(promise, cleanup);
            const result = await resourcePromise.wait();

            expect(result).toBe('success');
            expect(cleanup).toHaveBeenCalledOnce();
            expect(core.warning).toHaveBeenCalledWith(
                expect.stringContaining('Error during resource cleanup')
            );
        });

        it('should allow manual disposal', async () => {
            const cleanup = vi.fn();
            const promise = new Promise(() => {}); // Never resolves

            const resourcePromise = new ResourceAwarePromise(promise, cleanup);
            await resourcePromise.dispose();

            expect(cleanup).toHaveBeenCalledOnce();
        });

        it('should handle multiple dispose calls safely', async () => {
            const cleanup = vi.fn();
            const promise = Promise.resolve('success');

            const resourcePromise = new ResourceAwarePromise(promise, cleanup);
            await resourcePromise.dispose();
            await resourcePromise.dispose(); // Second disposal should be safe

            expect(cleanup).toHaveBeenCalledOnce();
        });
    });

    describe('Integration Tests', () => {
        it('should handle complex resource scenarios', async () => {
            const timeoutCallback = vi.fn();
            const intervalCallback = vi.fn();
            const cleanupCallback = vi.fn();

            await withResourceTracking(async (tracker) => {
                const timeout = createTrackedTimeout(tracker, timeoutCallback, 500);
                const interval = createTrackedInterval(tracker, intervalCallback, 200);
                
                timeout.start();
                interval.start();

                // Create a resource-aware promise
                const promise = new Promise(resolve => setTimeout(resolve, 100));
                const resourcePromise = new ResourceAwarePromise(promise, cleanupCallback);
                tracker.track(resourcePromise);

                vi.advanceTimersByTime(300);
                
                expect(intervalCallback).toHaveBeenCalledTimes(1);
                expect(timeoutCallback).not.toHaveBeenCalled();
                
                return 'completed';
            });

            // All resources should be disposed
            expect(cleanupCallback).toHaveBeenCalledOnce();
            
            // Advance more time - callbacks should not execute
            vi.advanceTimersByTime(1000);
            expect(timeoutCallback).not.toHaveBeenCalled();
            expect(intervalCallback).toHaveBeenCalledTimes(1); // Still just 1 from before
        });

        it('should track resource lifecycle accurately', async () => {
            const tracker = new ResourceTracker();
            const disposable1: Disposable = { dispose: vi.fn() };
            const disposable2: Disposable = { dispose: vi.fn() };

            expect(tracker.resourceCount).toBe(0);

            tracker.track(disposable1);
            expect(tracker.resourceCount).toBe(1);

            tracker.track(disposable2);
            expect(tracker.resourceCount).toBe(2);

            tracker.untrack(disposable1);
            expect(tracker.resourceCount).toBe(1);

            await tracker.dispose();
            expect(tracker.resourceCount).toBe(0);
            expect(tracker.isDisposed).toBe(true);

            expect(disposable1.dispose).not.toHaveBeenCalled();
            expect(disposable2.dispose).toHaveBeenCalledOnce();
        });
    });
});
