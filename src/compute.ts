import { CoverageBundle } from './schema.js';

export type Totals = {
    totalPct: number;
    diffPct: number;
    branchPct?: number;
    didBreachThresholds: boolean;
    linesCovered: number;
    linesTotal: number;
    diffLinesCovered: number;
    diffLinesTotal: number;
};

export type Thresholds = {
    total?: number;
    diff?: number;
    branches?: number;
};

/**
 * Compute coverage totals for a bundle and diff map
 * diffMap: { [filePath: string]: Set<number> }
 */
export function computeTotals(
    bundle: CoverageBundle, 
    diffMap: Record<string, Set<number>>,
    thresholds?: Thresholds
): Totals {
    let totalLinesCovered = 0;
    let totalLines = 0;
    let totalDiffCovered = 0;
    let totalDiffLines = 0;
    let totalBranchesCovered = 0;
    let totalBranches = 0;

    for (const file of bundle.files) {
        const linesCovered = file.lines.filter(l => l.hits > 0).length;
        const linesTotal = file.lines.length;

        totalLinesCovered += linesCovered;
        totalLines += linesTotal;

        // Branch coverage (if available)
        if (file.summary.branchesCovered !== undefined && file.summary.branchesTotal !== undefined) {
            totalBranchesCovered += file.summary.branchesCovered;
            totalBranches += file.summary.branchesTotal;
        }

        // Diff coverage for this file
        const changed = diffMap[file.path] ?? new Set<number>();
        for (const lineNumber of changed) {
            const line = file.lines.find(l => l.line === lineNumber);
            if (line) {
                totalDiffLines++;
                if (line.hits > 0) {
                    totalDiffCovered++;
                }
            }
        }
    }

    // Calculate percentages with proper rounding
    const totalPct = totalLines > 0 ? Math.round((totalLinesCovered / totalLines) * 10000) / 100 : 0;
    const diffPct = totalDiffLines > 0 ? Math.round((totalDiffCovered / totalDiffLines) * 10000) / 100 : 0;
    const branchPct = totalBranches > 0 ? Math.round((totalBranchesCovered / totalBranches) * 10000) / 100 : undefined;

    // Check thresholds
    let didBreachThresholds = false;
    if (thresholds) {
        if (thresholds.total !== undefined && totalPct < thresholds.total) {
            didBreachThresholds = true;
        }
        if (thresholds.diff !== undefined && diffPct < thresholds.diff) {
            didBreachThresholds = true;
        }
        if (thresholds.branches !== undefined && branchPct !== undefined && branchPct < thresholds.branches) {
            didBreachThresholds = true;
        }
    }

    return {
        totalPct,
        diffPct,
        branchPct,
        didBreachThresholds,
        linesCovered: totalLinesCovered,
        linesTotal: totalLines,
        diffLinesCovered: totalDiffCovered,
        diffLinesTotal: totalDiffLines
    };
}

export function parseThresholds(thresholdsString?: string): Thresholds | undefined {
    if (!thresholdsString) return undefined;
    
    const thresholds: Thresholds = {};
    const lines = thresholdsString.split(/\r?\n/);
    
    for (const line of lines) {
        const [key, value] = line.split(':').map(s => s.trim());
        if (key && value) {
            const numValue = parseFloat(value);
            if (!isNaN(numValue)) {
                switch (key.toLowerCase()) {
                case 'total':
                    thresholds.total = numValue;
                    break;
                case 'diff':
                    thresholds.diff = numValue;
                    break;
                case 'branches':
                    thresholds.branches = numValue;
                    break;
                }
            }
        }
    }
    
    return Object.keys(thresholds).length > 0 ? thresholds : undefined;
}