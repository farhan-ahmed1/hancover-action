import { renderComment, upsertStickyComment } from '../src/comment';
describe('Comment Rendering', () => {
    it('should render a markdown comment correctly', () => {
        const totals = {
            totalPct: 85,
            diffPct: 75,
            branchPct: 60,
        };
        const grouped = {};
        const thresholds = {
            total: 80,
            diff: 75,
        };
        const comment = renderComment({ totals, grouped, thresholds });
        expect(comment).toContain('### Coverage Report');
        expect(comment).toContain('Total Coverage: 85%');
        expect(comment).toContain('Diff Coverage: 75%');
        expect(comment).toContain('Branch Coverage: 60%');
    });
    it('should update an existing sticky comment', async () => {
        const mockUpsert = jest.fn();
        upsertStickyComment = mockUpsert;
        const md = '### Updated Comment';
        const mode = 'update';
        await upsertStickyComment(md, mode);
        expect(mockUpsert).toHaveBeenCalledWith(md, mode);
    });
});
