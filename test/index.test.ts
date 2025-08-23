import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as core from '@actions/core';

// Mock dependencies before importing index
vi.mock('@actions/core');
vi.mock('../src/core/enhanced-v2.js', () => ({
    runEnhancedCoverage: vi.fn()
}));

const mockSetFailed = vi.mocked(core.setFailed);

describe('index', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.resetModules(); // Reset module cache to ensure fresh imports
    });

    afterEach(() => {
        vi.resetAllMocks();
    });

    it('should run enhanced coverage successfully', async () => {
        const { runEnhancedCoverage } = await import('../src/core/enhanced-v2.js');
        vi.mocked(runEnhancedCoverage).mockResolvedValue(undefined);

        // Import and run the actual index module
        await import('../src/core/index.js');

        // Give a small delay for the async execution
        await new Promise(resolve => setTimeout(resolve, 10));

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).not.toHaveBeenCalled();
    });

    it('should handle errors from enhanced coverage', async () => {
        const { runEnhancedCoverage } = await import('../src/core/enhanced-v2.js');
        const error = new Error('Coverage processing failed');
        vi.mocked(runEnhancedCoverage).mockRejectedValue(error);

        // Import and run the actual index module
        await import('../src/core/index.js');

        // Give a small delay for the async execution
        await new Promise(resolve => setTimeout(resolve, 10));

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).toHaveBeenCalledWith('Coverage processing failed');
    });

    it('should handle non-Error objects', async () => {
        const { runEnhancedCoverage } = await import('../src/core/enhanced-v2.js');
        vi.mocked(runEnhancedCoverage).mockRejectedValue('String error');

        // Import and run the actual index module
        await import('../src/core/index.js');

        // Give a small delay for the async execution  
        await new Promise(resolve => setTimeout(resolve, 10));

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).toHaveBeenCalledWith('String error');
    });

    it('should handle null/undefined errors', async () => {
        const { runEnhancedCoverage } = await import('../src/core/enhanced-v2.js');
        vi.mocked(runEnhancedCoverage).mockRejectedValue(null);

        // Import and run the actual index module
        await import('../src/core/index.js');

        // Give a small delay for the async execution
        await new Promise(resolve => setTimeout(resolve, 10));

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).toHaveBeenCalledWith('null');
    });

    it('should handle errors without message property', async () => {
        const { runEnhancedCoverage } = await import('../src/core/enhanced-v2.js');
        const errorObject = { code: 'UNKNOWN_ERROR' };
        vi.mocked(runEnhancedCoverage).mockRejectedValue(errorObject);

        // Import and run the actual index module
        await import('../src/core/index.js');

        // Give a small delay for the async execution
        await new Promise(resolve => setTimeout(resolve, 10));

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).toHaveBeenCalledWith('[object Object]');
    });
});
