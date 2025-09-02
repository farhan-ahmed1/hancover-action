import { describe, it, expect } from 'vitest';
import { logger } from '../../src/infrastructure/logger.js';
import { performanceMonitor } from '../../src/infrastructure/performance-monitor.js';
import { validateInputs } from '../../src/infrastructure/input-validator.js';

describe('Easy Improvements Integration', () => {
    it('should create structured logs with correlation IDs', () => {
        const context = logger.createContext('test-operation', { testData: 'value' });
        
        expect(context).toHaveProperty('correlationId');
        expect(context).toHaveProperty('operation', 'test-operation');
        expect(context).toHaveProperty('startTime');
        expect(context).toHaveProperty('metadata.testData', 'value');
    });

    it('should measure performance of operations', async () => {
        const result = await performanceMonitor.measure(
            'test-operation',
            async () => {
                await new Promise(resolve => setTimeout(resolve, 10));
                return 'success';
            }
        );

        expect(result).toBe('success');
        
        const summary = performanceMonitor.getSummary();
        expect(summary.totalOperations).toBeGreaterThan(0);
        
        // Reset for clean tests
        performanceMonitor.reset();
    });

    it('should validate inputs with helpful error messages', () => {
        const validationResult = validateInputs({
            files: ['test.xml'],
            timeoutSeconds: 120,
            maxBytesPerFile: 50 * 1024 * 1024,
            maxTotalBytes: 200 * 1024 * 1024
        });

        expect(validationResult.success).toBe(true);
        expect(validationResult.errors).toHaveLength(0);
    });

    it('should provide helpful validation errors for invalid inputs', () => {
        const validationResult = validateInputs({
            files: [], // Empty files array
            timeoutSeconds: -1, // Invalid timeout
            maxBytesPerFile: 50 * 1024 * 1024,
            maxTotalBytes: 10 * 1024 * 1024 // Smaller than maxBytesPerFile
        });

        expect(validationResult.success).toBe(false);
        expect(validationResult.errors.length).toBeGreaterThan(0);
        
        // Check that we get helpful error messages
        const errorMessages = validationResult.errors.map((e: any) => e.message);
        expect(errorMessages.some((msg: string) => msg.includes('No coverage files'))).toBe(true);
    });
});
