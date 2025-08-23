import { describe, it, expect } from 'vitest';
import { computeTotals, parseThresholds } from '../src/core/compute.js';
import { ProjectCov } from '../src/processing/schema.js';

describe('Compute Coverage', () => {
    const sampleProject: ProjectCov = {
        files: [
            {
                path: 'src/file1.ts',
                lines: { covered: 3, total: 4 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 2, total: 3 },
                coveredLineNumbers: new Set([1, 3, 4])
            },
            {
                path: 'src/file2.ts',
                lines: { covered: 2, total: 3 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 1, total: 2 },
                coveredLineNumbers: new Set([1, 2])
            }
        ],
        totals: {
            lines: { covered: 5, total: 7 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 3, total: 5 }
        }
    };

    it('should compute total coverage correctly', () => {
        const totals = computeTotals(sampleProject, {});
        
        expect(totals.totalPct).toBe(71.43); // 5/7 * 100 = 71.43%
        expect(totals.linesCovered).toBe(5);
        expect(totals.linesTotal).toBe(7);
    });

    it('should compute diff coverage correctly', () => {
        const diffMap = {
            'src/file1.ts': new Set([1, 2]), // line 1 is covered, line 2 is not
            'src/file2.ts': new Set([3])     // line 3 is not covered
        };
        
        const totals = computeTotals(sampleProject, diffMap);
        
        expect(totals.diffPct).toBe(33.33); // 1/3 * 100 = 33.33%
        expect(totals.diffLinesCovered).toBe(1);
        expect(totals.diffLinesTotal).toBe(3);
    });

    it('should parse thresholds correctly', () => {
        const thresholds = parseThresholds('total:50\ndiff:80\nbranches:60');
        
        expect(thresholds).toEqual({
            total: 50,
            diff: 80,
            branches: 60
        });
    });

    it('should handle empty thresholds', () => {
        const thresholds = parseThresholds('');
        expect(thresholds).toBeUndefined();
    });

    it('should handle malformed thresholds', () => {
        const thresholds = parseThresholds('invalid:format\ntotal:not-a-number');
        expect(thresholds).toBeUndefined();
    });

    it('should check thresholds correctly', () => {
        const thresholds = {
            total: 80,
            diff: 50
        };
        
        const totals = computeTotals(sampleProject, {}, thresholds);
        
        expect(totals.didBreachThresholds).toBe(true); // 71.43% < 80%
    });

    it('should calculate delta coverage', () => {
        const baseline = {
            totalPct: 60,
            branchPct: 50,
            linesCovered: 3,
            linesTotal: 5,
            branchesCovered: 1,
            branchesTotal: 2
        };
        
        const totals = computeTotals(sampleProject, {}, undefined, baseline);
        
        expect(totals.deltaPct).toBeCloseTo(11.43, 2); // 71.43 - 60 = 11.43
    });
});
