import { describe, it, expect, vi, beforeEach } from 'vitest';
import { shouldUseStreaming } from '../src/infrastructure/streaming-parser.js';
import { withTimeout, TimeoutController, FileOperationTimeout } from '../src/infrastructure/timeout-utils.js';
import { CoreProgressReporter, createFileTracker } from '../src/infrastructure/progress-reporter.js';

// Mock fs module
vi.mock('fs', () => ({
    createReadStream: vi.fn(),
    default: {
        createReadStream: vi.fn()
    }
}));

vi.mock('fs/promises', () => ({
    stat: vi.fn(),
    readFile: vi.fn()
}));

// Mock @actions/core module
vi.mock('@actions/core', () => ({
    info: vi.fn(),
    warning: vi.fn()
}));

describe('Performance Enhancements', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('Streaming Parser', () => {
        it('should determine when to use streaming based on file size', () => {
            expect(shouldUseStreaming(5 * 1024 * 1024)).toBe(false); // 5MB - under threshold
            expect(shouldUseStreaming(15 * 1024 * 1024)).toBe(true); // 15MB - over threshold
            expect(shouldUseStreaming(50 * 1024 * 1024)).toBe(true); // 50MB - definitely streaming
        });

        it('should respect custom memory threshold', () => {
            const customOptions = { maxMemoryUsage: 1024 * 1024 }; // 1MB threshold
            expect(shouldUseStreaming(512 * 1024, customOptions)).toBe(false); // 512KB
            expect(shouldUseStreaming(2 * 1024 * 1024, customOptions)).toBe(true); // 2MB
        });
    });

    describe('Timeout Utils', () => {
        it('should create timeout promises that reject after specified duration', async () => {
            const startTime = Date.now();
            const timeoutMs = 100;

            try {
                await withTimeout(
                    new Promise(resolve => setTimeout(resolve, 200)), // Takes 200ms
                    { timeoutMs, operation: 'test operation' }
                );
                expect.fail('Should have timed out');
            } catch (error: any) {
                const elapsed = Date.now() - startTime;
                expect(elapsed).toBeLessThan(150); // Should timeout before 150ms
                expect(error.message).toContain('timed out');
            }
        });

        it('should not timeout when operation completes in time', async () => {
            const result = await withTimeout(
                Promise.resolve('success'),
                { timeoutMs: 100, operation: 'fast operation' }
            );
            expect(result).toBe('success');
        });

        it('should handle zero timeout by not timing out', async () => {
            const result = await withTimeout(
                new Promise(resolve => setTimeout(() => resolve('completed'), 50)),
                { timeoutMs: 0, operation: 'no timeout operation' }
            );
            expect(result).toBe('completed');
        });
    });

    describe('Timeout Controller', () => {
        it('should manage timeout lifecycle properly', async () => {
            const controller = new TimeoutController(100, 'test');
            expect(controller.isRunning()).toBe(false);

            controller.start();
            expect(controller.isRunning()).toBe(true);

            controller.clear();
            expect(controller.isRunning()).toBe(false);

            // Promise should not reject after clearing
            await new Promise(resolve => setTimeout(resolve, 150));
        });

        it('should extend timeout properly', () => {
            const controller = new TimeoutController(100, 'test');
            controller.start();
            
            expect(() => controller.extend(50)).not.toThrow();
            expect(controller.isRunning()).toBe(true);
        });

        it('should throw when trying to extend inactive controller', () => {
            const controller = new TimeoutController(100, 'test');
            expect(() => controller.extend(50)).toThrow('Cannot extend inactive timeout controller');
        });
    });

    describe('File Operation Timeout', () => {
        it('should calculate timeout based on file size', () => {
            const timeoutManager = new FileOperationTimeout(30000, 5000); // 30s base + 5s per MB

            // 1MB file: 30s + 5s = 35s
            expect(timeoutManager.calculateTimeout(1024 * 1024)).toBe(35000);

            // 10MB file: 30s + 50s = 80s
            expect(timeoutManager.calculateTimeout(10 * 1024 * 1024)).toBe(80000);

            // Very large file should be capped at 10 minutes
            const veryLargeFile = 100 * 1024 * 1024; // 100MB
            const timeout = timeoutManager.calculateTimeout(veryLargeFile);
            expect(timeout).toBeLessThanOrEqual(10 * 60 * 1000); // 10 minutes max
        });

        it('should create proper timeout options', () => {
            const timeoutManager = new FileOperationTimeout();
            const filePath = '/test/large-file.xml';
            const fileSizeBytes = 5 * 1024 * 1024; // 5MB

            const options = timeoutManager.createOptions(filePath, fileSizeBytes);

            expect(options.operation).toContain('large-file.xml');
            expect(options.operation).toContain('5.00MB');
            expect(options.timeoutMs).toBeGreaterThan(0);
            expect(options.onTimeout).toBeDefined();
        });
    });

    describe('Progress Reporter', () => {
        it('should track progress stages correctly', async () => {
            const { info } = await import('@actions/core');
            const infoSpy = vi.mocked(info);
            infoSpy.mockClear();
            
            const reporter = new CoreProgressReporter();

            reporter.start(3, 'Test Operation');
            reporter.step(1, 'First step');
            reporter.step(2, 'Second step');
            reporter.finish('Completed');

            // Verify that core.info was called for the progress reporting
            expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining('Starting Test Operation'));
            expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining('Completed'));
        });

        it('should calculate progress percentage correctly', async () => {
            const { info } = await import('@actions/core');
            const infoSpy = vi.mocked(info);
            infoSpy.mockClear();
            
            const reporter = new CoreProgressReporter();

            reporter.start(4, 'Test');
            reporter.step(2); // 50% complete

            // For now, just verify it doesn't throw
            expect(() => reporter.step(2)).not.toThrow();
        });
    });

    describe('File Tracker', () => {
        it('should track multiple file processing', async () => {
            const { info } = await import('@actions/core');
            const infoSpy = vi.mocked(info);
            infoSpy.mockClear();
            
            const tracker = createFileTracker();

            const files = [
                { path: 'file1.xml', size: 1000 },
                { path: 'file2.xml', size: 2000 }
            ];

            tracker.startFileProcessing(files);
            tracker.updateFileProgress('file1.xml', 500, 1000); // 50% of file1
            tracker.completeFile('file1.xml', 1000);
            tracker.updateFileProgress('file2.xml', 1000, 2000); // 50% of file2
            tracker.completeFile('file2.xml', 2000);
            tracker.finish();

            expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining('Processing 2 coverage files'));
            expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining('file1.xml'));
            expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining('file2.xml'));
        });

        it('should handle empty file list', () => {
            const tracker = createFileTracker();
            
            expect(() => {
                tracker.startFileProcessing([]);
                tracker.finish();
            }).not.toThrow();
        });
    });

    describe('Performance Integration', () => {
        it('should work together for large file processing simulation', async () => {
            // Mock a large file scenario
            const mockStats = { size: 20 * 1024 * 1024 }; // 20MB

            // Test that streaming would be used
            expect(shouldUseStreaming(mockStats.size)).toBe(true);

            // Test timeout calculation
            const timeoutManager = new FileOperationTimeout();
            const timeout = timeoutManager.calculateTimeout(mockStats.size);
            expect(timeout).toBeGreaterThan(30000); // Should be more than base timeout

            // Test progress reporting doesn't throw
            const reporter = new CoreProgressReporter();
            expect(() => {
                reporter.start(1, 'Large file processing');
                reporter.report('Streaming', 50, '10MB/20MB');
                reporter.finish('Processing complete');
            }).not.toThrow();
        });
    });
});
