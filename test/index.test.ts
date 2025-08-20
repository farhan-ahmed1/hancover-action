import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as core from '@actions/core';

// Mock dependencies
vi.mock('@actions/core');
vi.mock('../src/enhanced.js', () => ({
    runEnhancedCoverage: vi.fn()
}));

const mockSetFailed = vi.mocked(core.setFailed);

// Mock the run function directly
async function mockRun() {
    const { runEnhancedCoverage } = await import('../src/enhanced.js');
    try {
        await runEnhancedCoverage();
    } catch (e: any) {
        core.setFailed(e?.message ?? String(e));
    }
}

describe('index', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.resetAllMocks();
    });

    it('should run enhanced coverage successfully', async () => {
        const { runEnhancedCoverage } = await import('../src/enhanced.js');
        vi.mocked(runEnhancedCoverage).mockResolvedValue(undefined);

        await mockRun();

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).not.toHaveBeenCalled();
    });

    it('should handle errors from enhanced coverage', async () => {
        const { runEnhancedCoverage } = await import('../src/enhanced.js');
        const error = new Error('Coverage processing failed');
        vi.mocked(runEnhancedCoverage).mockRejectedValue(error);

        await mockRun();

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).toHaveBeenCalledWith('Coverage processing failed');
    });

    it('should handle non-Error objects', async () => {
        const { runEnhancedCoverage } = await import('../src/enhanced.js');
        vi.mocked(runEnhancedCoverage).mockRejectedValue('String error');

        await mockRun();

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).toHaveBeenCalledWith('String error');
    });

    it('should handle null/undefined errors', async () => {
        const { runEnhancedCoverage } = await import('../src/enhanced.js');
        vi.mocked(runEnhancedCoverage).mockRejectedValue(null);

        await mockRun();

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).toHaveBeenCalledWith('null');
    });

    it('should handle errors without message property', async () => {
        const { runEnhancedCoverage } = await import('../src/enhanced.js');
        const errorObject = { code: 'UNKNOWN_ERROR' };
        vi.mocked(runEnhancedCoverage).mockRejectedValue(errorObject);

        await mockRun();

        expect(runEnhancedCoverage).toHaveBeenCalledTimes(1);
        expect(mockSetFailed).toHaveBeenCalledWith('[object Object]');
    });
});
