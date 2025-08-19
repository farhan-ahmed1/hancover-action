import { ProjectCov } from './schema.js';

export type Totals = {
    totalPct: number;
    diffPct: number;
    branchPct?: number;
    didBreachThresholds: boolean;
    linesCovered: number;
    linesTotal: number;
    diffLinesCovered: number;
    diffLinesTotal: number;
    branchesCovered?: number;
    branchesTotal?: number;
    deltaPct?: number; // Coverage delta compared to baseline
};

export type BaselineTotals = {
    totalPct: number;
    branchPct?: number;
    linesCovered: number;
    linesTotal: number;
    branchesCovered?: number;
    branchesTotal?: number;
};

export type Thresholds = {
    total?: number;
    diff?: number;
    branches?: number;
};

/**
 * Compute coverage totals for a project and diff map
 * diffMap: { [filePath: string]: Set<number> }
 */
export function computeTotals(
    project: ProjectCov, 
    diffMap: Record<string, Set<number>>,
    thresholds?: Thresholds,
    baseline?: BaselineTotals
): Totals {
    let totalLinesCovered = 0;
    let totalLines = 0;
    let totalDiffCovered = 0;
    let totalDiffLines = 0;
    let totalBranchesCovered = 0;
    let totalBranches = 0;

    for (const file of project.files) {
        totalLinesCovered += file.lines.covered;
        totalLines += file.lines.total;

        // Branch coverage
        totalBranchesCovered += file.branches.covered;
        totalBranches += file.branches.total;

        // Diff coverage for this file
        const changed = diffMap[file.path] ?? new Set<number>();
        for (const lineNumber of changed) {
            if (file.coveredLineNumbers.has(lineNumber)) {
                totalDiffLines++;
                totalDiffCovered++;
            } else {
                // Check if this line exists in the file (within total lines)
                // For simplicity, assume all changed lines are valid
                totalDiffLines++;
            }
        }
    }

    // Calculate percentages with proper rounding
    const totalPct = totalLines > 0 ? Math.round((totalLinesCovered / totalLines) * 10000) / 100 : 0;
    const diffPct = totalDiffLines > 0 ? Math.round((totalDiffCovered / totalDiffLines) * 10000) / 100 : 0;
    const branchPct = totalBranches > 0 ? Math.round((totalBranchesCovered / totalBranches) * 10000) / 100 : undefined;
    
    // Calculate delta if baseline is provided
    const deltaPct = baseline ? totalPct - baseline.totalPct : undefined;

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
        diffLinesTotal: totalDiffLines,
        branchesCovered: totalBranches > 0 ? totalBranchesCovered : undefined,
        branchesTotal: totalBranches > 0 ? totalBranches : undefined,
        deltaPct
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