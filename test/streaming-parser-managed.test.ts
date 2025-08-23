import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    shouldUseStreaming,
    type StreamingParseOptions
} from '../src/streaming-parser-managed.js';

describe('Enhanced Streaming Parser with Resource Management', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('shouldUseStreaming', () => {
        it('should return false for small files under default threshold', () => {
            expect(shouldUseStreaming(5 * 1024 * 1024)).toBe(false); // 5MB
            expect(shouldUseStreaming(1024 * 1024)).toBe(false); // 1MB
            expect(shouldUseStreaming(500 * 1024)).toBe(false); // 500KB
        });

        it('should return true for large files over default threshold', () => {
            expect(shouldUseStreaming(15 * 1024 * 1024)).toBe(true); // 15MB
            expect(shouldUseStreaming(50 * 1024 * 1024)).toBe(true); // 50MB
            expect(shouldUseStreaming(100 * 1024 * 1024)).toBe(true); // 100MB
        });

        it('should respect custom maxMemoryUsage option', () => {
            const options: StreamingParseOptions = {
                maxMemoryUsage: 1024 * 1024 // 1MB threshold
            };

            expect(shouldUseStreaming(512 * 1024, options)).toBe(false); // 512KB
            expect(shouldUseStreaming(2 * 1024 * 1024, options)).toBe(true); // 2MB
        });

        it('should handle edge cases', () => {
            const threshold = 10 * 1024 * 1024; // 10MB default
            expect(shouldUseStreaming(threshold)).toBe(false); // Equal to threshold
            expect(shouldUseStreaming(threshold + 1)).toBe(true); // Just over threshold
            expect(shouldUseStreaming(0)).toBe(false);
            expect(shouldUseStreaming(-1)).toBe(false);
        });
    });
});
