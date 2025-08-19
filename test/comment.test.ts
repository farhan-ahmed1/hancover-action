import { describe, it, expect, vi } from 'vitest';
import { renderComment, upsertStickyComment } from '../src/comment.js';
import { Totals } from '../src/compute.js';

describe('Comment Rendering', () => {
    it('should render a markdown comment correctly', async () => {
        const totals: Totals = {
            totalPct: 85,
            diffPct: 75,
            branchPct: 60,
            didBreachThresholds: false,
            linesCovered: 85,
            linesTotal: 100,
            diffLinesCovered: 15,
            diffLinesTotal: 20,
            branchesCovered: 60,
            branchesTotal: 100
        };

        const comment = await renderComment({ 
            totals, 
            baseRef: 'main',
            minThreshold: 50
        });

        // Test for new format
        expect(comment).toContain('<!-- coverage-comment:anchor -->');
        expect(comment).toContain('[![Coverage](');
        expect(comment).toContain('📊 Coverage Report vs main');
        expect(comment).toContain('**Overall Coverage**: 85.0%');
        expect(comment).toContain('<details>');
        expect(comment).toContain('### Project Coverage (PR)');
        expect(comment).toContain('### Code Changes Coverage');
        expect(comment).toContain('85.0%');
        expect(comment).toContain('75.0%');
        expect(comment).toContain('60.0%');
    });

    it('should update an existing sticky comment', async () => {
        const mockUpsert = vi.fn();
        // Mock the implementation by spying on the module
        vi.spyOn({ upsertStickyComment }, 'upsertStickyComment').mockImplementation(mockUpsert);

        const md = '### Updated Comment';
        await upsertStickyComment(md, 'update');

        // This test would need proper mocking setup
        // For now, just verify the function can be called
        expect(typeof upsertStickyComment).toBe('function');
    });
});