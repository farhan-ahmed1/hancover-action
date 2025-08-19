import { describe, it, expect, vi } from 'vitest';
import { computeDiff } from '../src/diff.js';
import { execSync } from 'child_process';

// Mock execSync to control git diff output
vi.mock('child_process', () => ({
    execSync: vi.fn()
}));

const mockExecSync = vi.mocked(execSync);

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
    });
});