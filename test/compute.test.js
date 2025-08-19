import { computeTotals } from '../src/compute';
describe('computeTotals', () => {
    it('should compute totals correctly for a single file', () => {
        const bundle = {
            files: [
                {
                    path: 'src/example.ts',
                    lines: [
                        { line: 1, hits: 1 },
                        { line: 2, hits: 0 },
                        { line: 3, hits: 1 },
                    ],
                    summary: {
                        linesCovered: 2,
                        linesTotal: 3,
                        branchesCovered: 0,
                        branchesTotal: 0,
                    },
                },
            ],
        };
        const totals = computeTotals(bundle, {});
        expect(totals.totalPct).toBe(66.67);
        expect(totals.diffPct).toBe(0); // Assuming no diff coverage for this test
    });
    it('should handle multiple files', () => {
        const bundle = {
            files: [
                {
                    path: 'src/example1.ts',
                    lines: [
                        { line: 1, hits: 1 },
                        { line: 2, hits: 0 },
                    ],
                    summary: {
                        linesCovered: 1,
                        linesTotal: 2,
                        branchesCovered: 0,
                        branchesTotal: 0,
                    },
                },
                {
                    path: 'src/example2.ts',
                    lines: [
                        { line: 1, hits: 1 },
                        { line: 2, hits: 1 },
                        { line: 3, hits: 0 },
                    ],
                    summary: {
                        linesCovered: 2,
                        linesTotal: 3,
                        branchesCovered: 0,
                        branchesTotal: 0,
                    },
                },
            ],
        };
        const totals = computeTotals(bundle, {});
        expect(totals.totalPct).toBe(75); // (3/4)*100
        expect(totals.diffPct).toBe(0); // Assuming no diff coverage for this test
    });
});
