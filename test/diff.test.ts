import { describe, it, expect, vi } from 'vitest';
import { computeDiff } from '../src/diff.js';
import { execSync } from 'child_process';
import * as core from '@actions/core';

// Mock execSync to control git diff output
vi.mock('child_process', () => ({
    execSync: vi.fn()
}));

// Mock core functions
vi.mock('@actions/core', () => ({
    warning: vi.fn()
}));

const mockExecSync = vi.mocked(execSync);
const mockWarning = vi.mocked(core.warning);

describe('computeDiff', () => {
    it('should return an empty object for no changes', async () => {
        // Mock git diff with no output (no changes)
        mockExecSync.mockReturnValue('');
        
        const changedLines = await computeDiff('some-base-ref');
        expect(changedLines).toEqual({});
    });

    it('should return changed lines for modified files', async () => {
        // Mock git diff output with changes
        const mockGitOutput = `diff --git a/src/example.ts b/src/example.ts
index 1234567..abcdefg 100644
--- a/src/example.ts
+++ b/src/example.ts
@@ -1,3 +1,4 @@
 line 1
+new line 2
 line 3
 line 4`;
        
        mockExecSync.mockReturnValue(mockGitOutput);
        
        const changedLines = await computeDiff('some-base-ref');
        expect(changedLines).toEqual({
            'src/example.ts': new Set([1, 2, 3, 4])
        });
    });

    it('should handle git command failure gracefully', async () => {
        // Mock git diff throwing an error
        mockExecSync.mockImplementation(() => {
            throw new Error('git command failed');
        });
        
        const changedLines = await computeDiff('invalid-ref');
        expect(changedLines).toEqual({});
        
        // Verify warning was called with error message (line 58)
        expect(vi.mocked(core.warning)).toHaveBeenCalledWith('Failed to compute diff: git command failed');
    });

    it('should handle ENOBUFS error specifically', async () => {
        // Mock git diff throwing ENOBUFS error to cover line 53
        mockExecSync.mockImplementation(() => {
            const error = new Error('ENOBUFS: No buffer space available');
            error.message = 'Command failed: git diff --name-only HEAD~1 ENOBUFS: No buffer space available';
            throw error;
        });
        
        const changedLines = await computeDiff('some-ref');
        expect(changedLines).toEqual({});
        
        // Verify specific ENOBUFS warning was called (line 53)
        expect(vi.mocked(core.warning)).toHaveBeenCalledWith('Git diff output too large (ENOBUFS). Skipping diff coverage calculation.');
    });

    it('should handle non-Error objects thrown', async () => {
        // Mock git diff throwing a non-Error object to cover line 59 
        mockExecSync.mockImplementation(() => {
            throw 'String error message';
        });
        
        const changedLines = await computeDiff('some-ref');
        expect(changedLines).toEqual({});
        
        // Verify general error warning was called (line 59)
        expect(vi.mocked(core.warning)).toHaveBeenCalledWith('Failed to compute diff: String error message');
    });
});