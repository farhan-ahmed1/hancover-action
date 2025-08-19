import { describe, it, expect } from 'vitest';
import { computeTotals, parseThresholds } from '../src/compute.js';
import { CoverageBundle } from '../src/schema.js';

describe('Compute Coverage', () => {
    const sampleBundle: CoverageBundle = {
        files: [
            {
                path: 'src/file1.ts',
                lines: [
                    { line: 1, hits: 1 },
                    { line: 2, hits: 0 },
                    { line: 3, hits: 1 },
                    { line: 4, hits: 1 }
                ],
                summary: { linesCovered: 3, linesTotal: 4 }
            },
            {
                path: 'src/file2.ts',
                lines: [
                    { line: 1, hits: 1 },
                    { line: 2, hits: 1 },
                    { line: 3, hits: 0 }
                ],
                summary: { linesCovered: 2, linesTotal: 3 }
            }
        ]
    };

    it('should compute total coverage correctly', () => {
        const diffMap = {};
        const totals = computeTotals(sampleBundle, diffMap);

        expect(totals.totalPct).toBe(71.43); // 5/7 * 100 rounded to 2 decimals
        expect(totals.diffPct).toBe(0); // No diff lines
        expect(totals.linesCovered).toBe(5);
        expect(totals.linesTotal).toBe(7);
        expect(totals.didBreachThresholds).toBe(false);
    });

    it('should compute diff coverage correctly', () => {
        const diffMap = {
            'src/file1.ts': new Set([2, 3]), // lines 2 (not covered) and 3 (covered)
            'src/file2.ts': new Set([1, 3])  // lines 1 (covered) and 3 (not covered)
        };
        
        const totals = computeTotals(sampleBundle, diffMap);

        expect(totals.diffPct).toBe(50); // 2/4 * 100 = 50%
        expect(totals.diffLinesCovered).toBe(2);
        expect(totals.diffLinesTotal).toBe(4);
    });

    it('should check thresholds correctly', () => {
        const diffMap = {};
        const thresholds = { total: 80, diff: 60 };
        
        const totals = computeTotals(sampleBundle, diffMap, thresholds);

        expect(totals.didBreachThresholds).toBe(true); // 71.43% < 80%
    });

    it('should handle branch coverage', () => {
        const bundleWithBranches: CoverageBundle = {
            files: [{
                path: 'src/branches.ts',
                lines: [
                    { line: 1, hits: 1, isBranch: true, branchesHit: 2, branchesTotal: 4 }
                ],
                summary: { 
                    linesCovered: 1, 
                    linesTotal: 1,
                    branchesCovered: 2,
                    branchesTotal: 4
                }
            }]
        };

        const totals = computeTotals(bundleWithBranches, {});
        expect(totals.branchPct).toBe(50); // 2/4 * 100 = 50%
    });
});

describe('Parse Thresholds', () => {
    it('should parse threshold string correctly', () => {
        const thresholdString = `total:80
diff:75
branches:60`;
        
        const thresholds = parseThresholds(thresholdString);
        
        expect(thresholds).toEqual({
            total: 80,
            diff: 75,
            branches: 60
        });
    });

    it('should handle empty string', () => {
        const thresholds = parseThresholds('');
        expect(thresholds).toBeUndefined();
    });

    it('should ignore invalid lines', () => {
        const thresholdString = `total:80
invalid-line
diff:75
not-a-number:abc`;
        
        const thresholds = parseThresholds(thresholdString);
        
        expect(thresholds).toEqual({
            total: 80,
            diff: 75
        });
    });
});
