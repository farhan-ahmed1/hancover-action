import * as core from '@actions/core';
import * as github from '@actions/github';
import { readInputs } from './inputs';
import { collectCoverage } from './normalize';
import { computeDiff } from './diff';
import { groupCoverage } from './group';
import { computeTotals } from './compute';
import { renderComment, upsertStickyComment } from './comment';
async function run() {
    try {
        const ctx = github.context;
        const i = readInputs(ctx);
        const bundle = await collectCoverage(i.files, {
            maxBytesPerFile: i.maxBytesPerFile,
            maxTotalBytes: i.maxTotalBytes,
            timeoutSeconds: i.timeoutSeconds,
            strict: i.strict
        });
        const diff = await computeDiff(i.baseRef);
        const totals = computeTotals(bundle, diff);
        const grouped = groupCoverage(bundle, i.groups);
        const md = renderComment({ totals, grouped, thresholds: i.thresholds });
        await upsertStickyComment(md, i.commentMode);
        core.setOutput('total_coverage', totals.totalPct.toFixed(1));
        core.setOutput('diff_coverage', totals.diffPct.toFixed(1));
        if (totals.branchPct != null)
            core.setOutput('branch_coverage', totals.branchPct.toFixed(1));
        const failed = totals.didBreachThresholds && !i.warnOnly;
        if (failed)
            core.setFailed('Coverage thresholds not met.');
    }
    catch (e) {
        core.setFailed(e?.message ?? String(e));
    }
}
run();
