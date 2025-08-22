import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    createTimeoutPromise,
    withTimeout,
    TimeoutController,
    FileOperationTimeout,
    globalTimeoutManager,
    withFileTimeout,
    withBatchTimeout,
    type TimeoutOptions
} from '../src/timeout-utils.js';
import * as core from '@actions/core';

// Mock @actions/core
vi.mock('@actions/core', () => ({
    warning: vi.fn()
}));

describe('Timeout Utils', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
        vi.restoreAllMocks();
    });

    describe('createTimeoutPromise', () => {
        it('should create a promise that rejects after specified time', async () => {
            const timeoutPromise = createTimeoutPromise(100, 'test operation');
            
            vi.advanceTimersByTime(99);
            // Should not reject yet
            expect(timeoutPromise).toBeDefined();
            
            vi.advanceTimersByTime(2);
            await expect(timeoutPromise).rejects.toThrow('Operation \'test operation\' timed out after 100ms');
        });

        it('should include operation name in error message', async () => {
            const timeoutPromise = createTimeoutPromise(50, 'custom operation name');
            
            vi.advanceTimersByTime(51);
            await expect(timeoutPromise).rejects.toThrow('Operation \'custom operation name\' timed out after 50ms');
        });

        it('should handle zero timeout', async () => {
            const timeoutPromise = createTimeoutPromise(0, 'immediate');
            
            vi.advanceTimersByTime(1);
            await expect(timeoutPromise).rejects.toThrow('Operation \'immediate\' timed out after 0ms');
        });
    });

    describe('withTimeout', () => {
        it('should resolve when promise completes before timeout', async () => {
            const fastPromise = Promise.resolve('success');
            const options: TimeoutOptions = {
                timeoutMs: 100,
                operation: 'fast operation'
            };

            const result = await withTimeout(fastPromise, options);
            expect(result).toBe('success');
        });

        it('should reject when promise times out', async () => {
            const slowPromise = new Promise(resolve => setTimeout(resolve, 200));
            const options: TimeoutOptions = {
                timeoutMs: 100,
                operation: 'slow operation'
            };

            const timeoutTest = withTimeout(slowPromise, options);
            
            vi.advanceTimersByTime(101);
            await expect(timeoutTest).rejects.toThrow('Operation \'slow operation\' timed out after 100ms');
        });

        it('should call onTimeout callback when timeout occurs', async () => {
            const onTimeoutSpy = vi.fn();
            const slowPromise = new Promise(resolve => setTimeout(resolve, 200));
            const options: TimeoutOptions = {
                timeoutMs: 100,
                operation: 'callback test',
                onTimeout: onTimeoutSpy
            };

            const timeoutTest = withTimeout(slowPromise, options);
            
            vi.advanceTimersByTime(101);
            await expect(timeoutTest).rejects.toThrow();
            expect(onTimeoutSpy).toHaveBeenCalled();
        });

        it('should not call onTimeout for non-timeout errors', async () => {
            const onTimeoutSpy = vi.fn();
            const failingPromise = Promise.reject(new Error('Other error'));
            const options: TimeoutOptions = {
                timeoutMs: 100,
                operation: 'failing operation',
                onTimeout: onTimeoutSpy
            };

            await expect(withTimeout(failingPromise, options)).rejects.toThrow('Other error');
            expect(onTimeoutSpy).not.toHaveBeenCalled();
        });

        it('should return promise directly when timeout is zero or negative', async () => {
            const promise = Promise.resolve('no timeout');
            
            const resultZero = await withTimeout(promise, { timeoutMs: 0, operation: 'test' });
            expect(resultZero).toBe('no timeout');

            const promiseNegative = Promise.resolve('negative timeout');
            const resultNegative = await withTimeout(promiseNegative, { timeoutMs: -1, operation: 'test' });
            expect(resultNegative).toBe('negative timeout');
        });
    });

    describe('TimeoutController', () => {
        it('should manage timeout state correctly', () => {
            const controller = new TimeoutController(100, 'test controller');
            
            expect(controller.isRunning()).toBe(false);
            
            controller.start();
            expect(controller.isRunning()).toBe(true);
            
            controller.clear();
            expect(controller.isRunning()).toBe(false);
        });

        it('should reject when timeout expires', async () => {
            const controller = new TimeoutController(100, 'expiring controller');
            
            const timeoutPromise = controller.start();
            
            vi.advanceTimersByTime(101);
            await expect(timeoutPromise).rejects.toThrow('Operation \'expiring controller\' timed out after 100ms');
            expect(controller.isRunning()).toBe(false);
        });

        it('should clear timeout and prevent rejection', async () => {
            const controller = new TimeoutController(100, 'cleared controller');
            
            controller.start();
            
            vi.advanceTimersByTime(50);
            controller.clear();
            
            vi.advanceTimersByTime(100);
            // Should not reject after clearing
            expect(controller.isRunning()).toBe(false);
        });

        it('should throw when starting already active controller', () => {
            const controller = new TimeoutController(100, 'double start');
            
            controller.start();
            expect(() => controller.start()).toThrow('Timeout controller is already active');
        });

        it('should throw when extending inactive controller', () => {
            const controller = new TimeoutController(100, 'extend inactive');
            
            expect(() => controller.extend(50)).toThrow('Cannot extend inactive timeout controller');
        });

        it('should extend timeout successfully when active', () => {
            const controller = new TimeoutController(100, 'extendable');
            
            controller.start();
            expect(() => controller.extend(50)).not.toThrow();
            expect(controller.isRunning()).toBe(true);
        });

        it('should handle zero timeout (no timeout)', () => {
            const controller = new TimeoutController(0, 'no timeout');
            
            // Should not create actual timeout
            controller.start();
            expect(controller.isRunning()).toBe(true);
            
            vi.advanceTimersByTime(1000);
            // Should still be running since no timeout was set
            expect(controller.isRunning()).toBe(true);
        });

        it('should handle negative timeout (no timeout)', () => {
            const controller = new TimeoutController(-1, 'negative timeout');
            
            controller.start();
            expect(controller.isRunning()).toBe(true);
            
            vi.advanceTimersByTime(1000);
            expect(controller.isRunning()).toBe(true);
        });

        it('should log warning when timeout expires', async () => {
            const controller = new TimeoutController(100, 'warning test');
            
            const timeoutPromise = controller.start();
            
            vi.advanceTimersByTime(101);
            await expect(timeoutPromise).rejects.toThrow();
            
            expect(vi.mocked(core.warning)).toHaveBeenCalledWith(
                'Operation \'warning test\' exceeded timeout of 100ms'
            );
        });
    });

    describe('FileOperationTimeout', () => {
        it('should calculate timeout based on file size with defaults', () => {
            const fileTimeout = new FileOperationTimeout();
            
            // 1MB file: 30s + 5s = 35s
            expect(fileTimeout.calculateTimeout(1024 * 1024)).toBe(35000);
            
            // 10MB file: 30s + 50s = 80s
            expect(fileTimeout.calculateTimeout(10 * 1024 * 1024)).toBe(80000);
            
            // 0MB file: just base timeout
            expect(fileTimeout.calculateTimeout(0)).toBe(30000);
        });

        it('should use custom base and per-MB timeouts', () => {
            const fileTimeout = new FileOperationTimeout(60000, 10000); // 60s base + 10s per MB
            
            // 1MB file: 60s + 10s = 70s
            expect(fileTimeout.calculateTimeout(1024 * 1024)).toBe(70000);
            
            // 5MB file: 60s + 50s = 110s
            expect(fileTimeout.calculateTimeout(5 * 1024 * 1024)).toBe(110000);
        });

        it('should cap timeout at maximum (10 minutes)', () => {
            const fileTimeout = new FileOperationTimeout();
            
            // Very large file that would exceed max
            const veryLargeFile = 200 * 1024 * 1024; // 200MB
            const timeout = fileTimeout.calculateTimeout(veryLargeFile);
            
            expect(timeout).toBe(10 * 60 * 1000); // 10 minutes max
        });

        it('should create proper timeout options', () => {
            const fileTimeout = new FileOperationTimeout();
            const filePath = '/test/large-coverage.xml';
            const fileSizeBytes = 5 * 1024 * 1024; // 5MB
            
            const options = fileTimeout.createOptions(filePath, fileSizeBytes);
            
            expect(options.operation).toContain('large-coverage.xml');
            expect(options.operation).toContain('5.00MB');
            expect(options.timeoutMs).toBe(55000); // 30s + 25s for 5MB
            expect(options.onTimeout).toBeDefined();
            
            // Test onTimeout callback
            options.onTimeout!();
            expect(vi.mocked(core.warning)).toHaveBeenCalledWith(
                expect.stringContaining('File processing timeout: /test/large-coverage.xml (5.00MB)')
            );
        });

        it('should handle fractional MB sizes correctly', () => {
            const fileTimeout = new FileOperationTimeout();
            
            // 1.5MB file
            const fileSizeBytes = 1.5 * 1024 * 1024;
            const timeout = fileTimeout.calculateTimeout(fileSizeBytes);
            
            expect(timeout).toBe(37500); // 30s + 7.5s
        });
    });

    describe('globalTimeoutManager', () => {
        it('should be properly initialized with defaults', () => {
            // Test that global instance works
            const timeout = globalTimeoutManager.calculateTimeout(1024 * 1024);
            expect(timeout).toBe(35000); // 30s + 5s for 1MB
        });

        it('should create options using global instance', () => {
            const options = globalTimeoutManager.createOptions('/test/file.xml', 2 * 1024 * 1024);
            expect(options.timeoutMs).toBe(40000); // 30s + 10s for 2MB
        });
    });

    describe('withFileTimeout', () => {
        it('should apply file-size-based timeout', async () => {
            const fastOperation = Promise.resolve('completed');
            const filePath = '/test/small.xml';
            const fileSizeBytes = 1024 * 1024; // 1MB
            
            const result = await withFileTimeout(fastOperation, filePath, fileSizeBytes);
            expect(result).toBe('completed');
        });

        it('should timeout long operations based on file size', async () => {
            const slowOperation = new Promise(resolve => setTimeout(resolve, 100000));
            const filePath = '/test/tiny.xml';
            const fileSizeBytes = 1024; // 1KB - very short timeout
            
            const timeoutTest = withFileTimeout(slowOperation, filePath, fileSizeBytes);
            
            // Advance beyond the calculated timeout (30s + very small amount)
            vi.advanceTimersByTime(31000);
            await expect(timeoutTest).rejects.toThrow();
        });

        it('should use custom timeout when provided', async () => {
            const operation = new Promise(resolve => setTimeout(resolve, 200));
            const filePath = '/test/custom.xml';
            const fileSizeBytes = 10 * 1024 * 1024; // Large file
            const customTimeout = 100; // But short custom timeout
            
            const timeoutTest = withFileTimeout(operation, filePath, fileSizeBytes, customTimeout);
            
            vi.advanceTimersByTime(101);
            await expect(timeoutTest).rejects.toThrow();
        });

        it('should log warning on timeout with file details', async () => {
            const slowOperation = new Promise(resolve => setTimeout(resolve, 100000));
            const filePath = '/test/timeout-test.xml';
            const fileSizeBytes = 2 * 1024 * 1024; // 2MB
            
            const timeoutTest = withFileTimeout(slowOperation, filePath, fileSizeBytes);
            
            vi.advanceTimersByTime(41000); // Beyond 40s timeout for 2MB
            await expect(timeoutTest).rejects.toThrow();
            
            expect(vi.mocked(core.warning)).toHaveBeenCalledWith(
                expect.stringContaining('File operation timed out: /test/timeout-test.xml (2.0MB)')
            );
        });
    });

    describe('withBatchTimeout', () => {
        it('should complete all operations within timeout', async () => {
            const operations = [
                () => Promise.resolve('result1'),
                () => Promise.resolve('result2'),
                () => Promise.resolve('result3')
            ];
            
            const results = await withBatchTimeout(operations, 1000, 'test batch');
            expect(results).toEqual(['result1', 'result2', 'result3']);
        });

        it('should timeout batch operations', async () => {
            const operations = [
                () => new Promise(resolve => setTimeout(() => resolve('fast'), 50)),
                () => new Promise(resolve => setTimeout(() => resolve('slow'), 200)),
            ];
            
            const batchTest = withBatchTimeout(operations, 100, 'slow batch');
            
            vi.advanceTimersByTime(101);
            await expect(batchTest).rejects.toThrow('Operation \'Batch operation: slow batch\' timed out after 100ms');
        });

        it('should clear timeout controller when completed successfully', async () => {
            const operations = [
                () => Promise.resolve('quick')
            ];
            
            const results = await withBatchTimeout(operations, 1000, 'quick batch');
            expect(results).toEqual(['quick']);
            
            // Controller should be cleared - no timeout should fire
            vi.advanceTimersByTime(2000);
            // No additional expectations - just ensure no uncaught rejections
        });

        it('should clear timeout controller when operation fails', async () => {
            const operations = [
                () => Promise.reject(new Error('operation failed'))
            ];
            
            await expect(withBatchTimeout(operations, 1000, 'failing batch')).rejects.toThrow('operation failed');
            
            // Controller should be cleared
            vi.advanceTimersByTime(2000);
        });

        it('should handle empty operations array', async () => {
            const results = await withBatchTimeout([], 1000, 'empty batch');
            expect(results).toEqual([]);
        });

        it('should handle mix of successful and failing operations', async () => {
            const operations = [
                () => Promise.resolve('success'),
                () => Promise.reject(new Error('failure'))
            ];
            
            await expect(withBatchTimeout(operations, 1000, 'mixed batch')).rejects.toThrow('failure');
        });
    });

    describe('error handling edge cases', () => {
        it('should handle timeout controller race conditions', () => {
            const controller = new TimeoutController(100, 'race test');
            
            controller.start();
            controller.clear();
            
            // Should be safe to clear multiple times
            expect(() => controller.clear()).not.toThrow();
            expect(controller.isRunning()).toBe(false);
        });

        it('should handle extend after timeout expiry', async () => {
            const controller = new TimeoutController(50, 'extend after expiry');
            
            const timeoutPromise = controller.start();
            
            vi.advanceTimersByTime(51);
            await expect(timeoutPromise).rejects.toThrow();
            
            // Should not be able to extend after expiry
            expect(() => controller.extend(100)).toThrow('Cannot extend inactive timeout controller');
        });

        it('should handle file timeout with zero file size', async () => {
            const operation = Promise.resolve('empty file');
            const result = await withFileTimeout(operation, '/test/empty.xml', 0);
            expect(result).toBe('empty file');
        });

        it('should handle negative file sizes gracefully', async () => {
            const operation = Promise.resolve('negative size');
            // Negative sizes should be treated as 0
            const result = await withFileTimeout(operation, '/test/negative.xml', -100);
            expect(result).toBe('negative size');
        });
    });
});
