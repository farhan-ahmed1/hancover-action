import { describe, it, expect } from 'vitest';
import { renderComment } from '../src/comment.js';
import { Totals } from '../src/compute.js';
import { GroupSummary } from '../src/group.js';

describe('Comment Rendering', () => {
    const sampleTotals: Totals = {
        totalPct: 85.5,
        diffPct: 75.25,
        branchPct: 60.0,
        didBreachThresholds: false,
        linesCovered: 171,
        linesTotal: 200,
        diffLinesCovered: 15,
        diffLinesTotal: 20
    };

    const sampleGroups: GroupSummary[] = [
        {
            name: 'apps',
            files: [],
            coveragePct: 90.0,
            linesCovered: 90,
            linesTotal: 100
        },
        {
            name: 'packages',
            files: [],
            coveragePct: 80.0,
            linesCovered: 80,
            linesTotal: 100
        }
    ];

    it('should render a markdown comment correctly', async () => {
        const comment = await renderComment({ 
            totals: sampleTotals, 
            grouped: sampleGroups,
            thresholds: { total: 80, diff: 70 }
        });

        expect(comment).toContain('<!-- hancover:sticky -->');
        expect(comment).toContain('## 📊 Coverage Report');
        expect(comment).toContain('**Total Coverage** | 85.5%');
        expect(comment).toContain('**Diff Coverage** | 75.3%');
        expect(comment).toContain('**Branch Coverage** | 60.0%');
        expect(comment).toContain('- **apps**: 90.0%');
        expect(comment).toContain('- **packages**: 80.0%');
        expect(comment).toContain('✅ **All coverage thresholds met**');
    });

    it('should show threshold breach warning', async () => {
        const failingTotals = { ...sampleTotals, didBreachThresholds: true };
        
        const comment = await renderComment({ 
            totals: failingTotals,
            thresholds: { total: 90, diff: 80 }
        });

        expect(comment).toContain('⚠️ **Coverage thresholds not met**');
        expect(comment).toContain('❌');
    });

    it('should handle missing groups', async () => {
        const comment = await renderComment({ 
            totals: sampleTotals
        });

        expect(comment).toContain('No groups found.');
        expect(comment).toContain('Not configured');
    });

    it('should include base ref in title when provided', async () => {
        const comment = await renderComment({ 
            totals: sampleTotals,
            baseRef: 'main'
        });

        expect(comment).toContain('## 📊 Coverage Report vs main');
    });
});
