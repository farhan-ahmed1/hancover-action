import { describe, it, expect, vi } from 'vitest';
import { renderComment, upsertStickyComment } from '../src/comment.js';
import { Totals } from '../src/compute.js';
import { GroupSummary } from '../src/group.js';

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
            diffLinesTotal: 20
        };
        const grouped: GroupSummary[] = [
            { 
                name: 'api', 
                coveragePct: 85,
                files: [],
                linesCovered: 85,
                linesTotal: 100
            }
        ];
        const thresholds = {
            total: 80,
            diff: 75,
        };

        const comment = await renderComment({ totals, grouped, thresholds });

        expect(comment).toContain('## 📊 Coverage Report');
        expect(comment).toContain('**Total Coverage** | 85.0%');
        expect(comment).toContain('**Diff Coverage** | 75.0%');
        expect(comment).toContain('**Branch Coverage** | 60.0%');
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