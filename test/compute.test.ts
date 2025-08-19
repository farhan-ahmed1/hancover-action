import { describe, it, expect } from 'vitest';
import { ProjectCov } from '../src/schema.js';
import { computeTotals } from '../src/compute.js';

describe('computeTotals', () => {
    it('should compute totals correctly for a single file', () => {
        const project: ProjectCov = {
            files: [
                {
                    path: 'src/example.ts',
                    lines: { covered: 2, total: 3 },
                    branches: { covered: 0, total: 0 },
                    functions: { covered: 1, total: 2 },
                    coveredLineNumbers: new Set([1, 3])
                },
            ],
            totals: {
                lines: { covered: 2, total: 3 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 1, total: 2 }
            }
        };

        const totals = computeTotals(project, {});

        expect(totals.totalPct).toBe(66.67);
        expect(totals.diffPct).toBe(0); // Assuming no diff coverage for this test
    });

    it('should handle multiple files correctly', () => {
        const project: ProjectCov = {
            files: [
                {
                    path: 'src/example1.ts',
                    lines: { covered: 1, total: 2 },
                    branches: { covered: 0, total: 0 },
                    functions: { covered: 0, total: 1 },
                    coveredLineNumbers: new Set([1])
                },
                {
                    path: 'src/example2.ts',
                    lines: { covered: 2, total: 3 },
                    branches: { covered: 0, total: 0 },
                    functions: { covered: 1, total: 1 },
                    coveredLineNumbers: new Set([1, 2])
                },
            ],
            totals: {
                lines: { covered: 3, total: 5 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 1, total: 2 }
            }
        };

        const totals = computeTotals(project, {});

        expect(totals.totalPct).toBe(60); // (3/5)*100 = 60%
        expect(totals.diffPct).toBe(0); // Assuming no diff coverage for this test
    });
});
