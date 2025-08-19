import { describe, it, expect } from 'vitest';
import { groupCoverage, computeGroupSummaries } from '../src/group.js';
import { CoverageBundle } from '../src/schema.js';

describe('Group Coverage', () => {
    const sampleBundle: CoverageBundle = {
        files: [
            {
                path: 'apps/web/src/index.ts',
                lines: [
                    { line: 1, hits: 1 },
                    { line: 2, hits: 0 },
                    { line: 3, hits: 1 }
                ],
                summary: { linesCovered: 2, linesTotal: 3 }
            },
            {
                path: 'apps/api/src/server.ts',
                lines: [
                    { line: 1, hits: 1 },
                    { line: 2, hits: 1 }
                ],
                summary: { linesCovered: 2, linesTotal: 2 }
            },
            {
                path: 'packages/utils/index.ts',
                lines: [
                    { line: 1, hits: 0 },
                    { line: 2, hits: 1 }
                ],
                summary: { linesCovered: 1, linesTotal: 2 }
            }
        ]
    };

    it('should auto-group by first path segment', () => {
        const grouped = groupCoverage(sampleBundle);
        
        expect(grouped.size).toBe(2);
        expect(grouped.has('apps')).toBe(true);
        expect(grouped.has('packages')).toBe(true);
        
        expect(grouped.get('apps')).toHaveLength(2);
        expect(grouped.get('packages')).toHaveLength(1);
    });

    it('should handle user-defined groups', () => {
        const customGroups = [
            {
                name: 'frontend',
                include: ['apps/web/*', 'packages/ui/*']
            },
            {
                name: 'backend',
                include: ['apps/api/*']
            }
        ];

        const grouped = groupCoverage(sampleBundle, customGroups);
        
        expect(grouped.has('frontend')).toBe(true);
        expect(grouped.has('backend')).toBe(true);
        expect(grouped.get('frontend')).toHaveLength(1);
        expect(grouped.get('backend')).toHaveLength(1);
    });

    it('should compute group summaries correctly', () => {
        const grouped = groupCoverage(sampleBundle);
        const summaries = computeGroupSummaries(grouped);
        
        expect(summaries).toHaveLength(2);
        
        const appsGroup = summaries.find(s => s.name === 'apps');
        expect(appsGroup).toBeDefined();
        expect(appsGroup!.coveragePct).toBe(80); // (2+2)/(3+2) * 100 = 80%
        expect(appsGroup!.linesCovered).toBe(4);
        expect(appsGroup!.linesTotal).toBe(5);
        
        const packagesGroup = summaries.find(s => s.name === 'packages');
        expect(packagesGroup).toBeDefined();
        expect(packagesGroup!.coveragePct).toBe(50); // 1/2 * 100 = 50%
    });
});
