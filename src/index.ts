import * as core from '@actions/core';
import { readInputs } from './inputs.js';
import { collectCoverage } from './normalize.js';
import { computeDiff } from './diff.js';
import { groupCoverage, computeGroupSummaries } from './group.js';
import { computeTotals, parseThresholds, BaselineTotals } from './compute.js';
import { renderComment, upsertStickyComment } from './comment.js';

async function run() {
    try {
        const i = readInputs();

        const bundle = await collectCoverage(
            i.files, 
            i.maxBytesPerFile, 
            i.maxTotalBytes, 
            i.strict
        );

        const diff = await computeDiff(i.baseRef);
        const thresholds = parseThresholds(i.thresholds);

        // Collect baseline coverage if baseline files are provided
        let baseline: BaselineTotals | undefined;
        if (i.baselineFiles && i.baselineFiles.length > 0) {
            try {
                const baselineBundle = await collectCoverage(
                    i.baselineFiles, 
                    i.maxBytesPerFile, 
                    i.maxTotalBytes, 
                    i.strict
                );
                
                // Compute baseline totals
                const baselineTotals = computeTotals(baselineBundle, {}, thresholds);
                baseline = {
                    totalPct: baselineTotals.totalPct,
                    branchPct: baselineTotals.branchPct,
                    linesCovered: baselineTotals.linesCovered,
                    linesTotal: baselineTotals.linesTotal,
                    branchesCovered: baselineTotals.branchesCovered,
                    branchesTotal: baselineTotals.branchesTotal
                };
            } catch (error) {
                core.warning(`Failed to process baseline coverage files: ${error}`);
            }
        }
        
        const totals = computeTotals(bundle, diff, thresholds, baseline);
        
        const grouped = groupCoverage(bundle, i.groups);
        const groupSummaries = computeGroupSummaries(grouped);

        const md = await renderComment({ 
            totals, 
            baseline,
            grouped: groupSummaries, 
            thresholds,
            baseRef: i.baseRef,
            minThreshold: i.minThreshold
        });

        await upsertStickyComment(md, i.commentMode);

        core.setOutput('total_coverage', totals.totalPct.toFixed(1));
        core.setOutput('diff_coverage', totals.diffPct.toFixed(1));
        if (totals.branchPct != null) core.setOutput('branch_coverage', totals.branchPct.toFixed(1));
        if (totals.deltaPct != null) core.setOutput('delta_coverage', totals.deltaPct.toFixed(1));

        const failed = totals.didBreachThresholds && !i.warnOnly;
        if (failed) core.setFailed('Coverage thresholds not met.');
    } catch (e: any) {
        core.setFailed(e?.message ?? String(e));
    }
}

run();
