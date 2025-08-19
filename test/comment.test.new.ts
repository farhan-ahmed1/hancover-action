import { describe, it, expect } from 'vitest';
import { renderComment } from '../src/comment.js';
import { Totals } from '../src/compute.js';

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

    it('should render a markdown comment correctly', async () => {
        const comment = await renderComment({ 
            totals: sampleTotals, 
            baseRef: 'main',
            minThreshold: 50
        });

        expect(comment).toContain('<!-- coverage-comment:anchor -->');
        expect(comment).toContain('📊 Coverage Report vs main');
        expect(comment).toContain('**Overall Coverage**: 85.5%');
        expect(comment).toContain('### Project Coverage (PR)');
        expect(comment).toContain('### Code Changes Coverage');
        expect(comment).toContain('✅ **All coverage thresholds met**');
    });

    it('should show threshold breach warning', async () => {
        const failingTotals = { ...sampleTotals, didBreachThresholds: true };
        
        const comment = await renderComment({ 
            totals: failingTotals,
            baseRef: 'main',
            minThreshold: 50
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
