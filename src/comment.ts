import * as core from '@actions/core';
import * as github from '@actions/github';
import { Totals, BaselineTotals } from './compute.js';
import { GroupSummary } from './group.js';
import { generateCoverageBadge, generateDeltaBadge, getHealthIcon } from './badges.js';

const COVERAGE_COMMENT_MARKER = '<!-- coverage-comment:anchor -->';

export interface CommentData {
    totals: Totals;
    baseline?: BaselineTotals;
    grouped?: GroupSummary[];
    thresholds?: any;
    baseRef?: string;
    minThreshold?: number;
}

export async function renderComment({ 
    totals, 
    baseline,
    grouped, 
    thresholds,
    baseRef,
    minThreshold = 50
}: CommentData): Promise<string> {
    // Generate badges
    const coverageBadge = generateCoverageBadge(totals.totalPct);
    const deltaBadge = totals.deltaPct !== undefined ? generateDeltaBadge(totals.deltaPct) : null;

    // Badge section
    let badgeSection = `[![Coverage](${coverageBadge})](#)`;
    if (deltaBadge) {
        badgeSection += `\n[![Δ vs main](${deltaBadge})](#)`;
    }

    // Project Coverage table
    const projectTable = renderCoverageTable({
        title: 'Project Coverage (PR)',
        lineRate: totals.totalPct,
        branchRate: totals.branchPct,
        linesHit: totals.linesCovered,
        linesTotal: totals.linesTotal,
        branchesHit: totals.branchesCovered,
        branchesTotal: totals.branchesTotal,
        minThreshold
    });

    // Code Changes Coverage table  
    const changesTable = renderCoverageTable({
        title: 'Code Changes Coverage',
        lineRate: totals.diffPct,
        branchRate: undefined, // Branch coverage for changes not typically available
        linesHit: totals.diffLinesCovered,
        linesTotal: totals.diffLinesTotal,
        branchesHit: undefined,
        branchesTotal: undefined,
        minThreshold
    });

    // Groups section (if available)
    const groupsSection = grouped && grouped.length > 0 
        ? `\n### 📈 Coverage by Group\n\n${grouped.map(g => 
            `- **${g.name}**: ${g.coveragePct.toFixed(1)}% (${g.linesCovered}/${g.linesTotal} lines)`
        ).join('\n')}\n`
        : '';

    const comparisonText = baseRef ? ` vs ${baseRef}` : '';

    return `${COVERAGE_COMMENT_MARKER}
${badgeSection}

<details>
<summary><b>Code Coverage${comparisonText}</b> &nbsp;|&nbsp; <i>expand for full summary</i></summary>

<br/>

${projectTable}

---

${changesTable}
${groupsSection}
### 📋 Summary

- **Lines Covered**: ${totals.linesCovered}/${totals.linesTotal}
- **Changed Lines Covered**: ${totals.diffLinesCovered}/${totals.diffLinesTotal}
${baseline ? `- **Coverage Delta**: ${totals.deltaPct?.toFixed(1)}%` : ''}
- **Thresholds**: ${thresholds ? JSON.stringify(thresholds, null, 2) : 'Not configured'}

${totals.didBreachThresholds ? '⚠️ **Coverage thresholds not met**' : '✅ **All coverage thresholds met**'}

</details>
`;
}

interface TableConfig {
    title: string;
    lineRate: number;
    branchRate?: number;
    linesHit: number;
    linesTotal: number;
    branchesHit?: number;
    branchesTotal?: number;
    minThreshold: number;
}

function renderCoverageTable(config: TableConfig): string {
    const {
        title,
        lineRate,
        branchRate,
        linesHit,
        linesTotal,
        branchesHit,
        branchesTotal,
        minThreshold
    } = config;

    const lineHealth = getHealthIcon(lineRate, minThreshold);
    
    const branchRateDisplay = branchRate !== undefined ? `${branchRate.toFixed(1)}%` : 'N/A';
    const branchSummary = branchesHit !== undefined && branchesTotal !== undefined 
        ? `(${branchesHit} / ${branchesTotal})` 
        : '';

    return `### ${title}
| Package | Line Rate | Branch Rate | Health |
|---|---:|---:|:---:|
| main | ${lineRate.toFixed(1)}% | ${branchRateDisplay} | ${lineHealth} |
| **Summary** | **${lineRate.toFixed(1)}% (${linesHit} / ${linesTotal})** | **${branchRateDisplay} ${branchSummary}** | **${lineHealth}** |

_Minimum pass threshold is ${minThreshold.toFixed(1)}%_`;
}

export async function upsertStickyComment(md: string, mode: 'update' | 'new' = 'update'): Promise<void> {
    try {
        const token = core.getInput('github-token') || process.env.GITHUB_TOKEN;
        if (!token) {
            core.warning('No GitHub token provided, skipping comment update');
            return;
        }

        const octokit = github.getOctokit(token);
        const context = github.context;
        
        // Only work with pull requests
        if (!context.payload.pull_request) {
            core.info('Not a pull request, skipping comment');
            return;
        }

        const { owner, repo } = context.repo;
        const pull_number = context.payload.pull_request.number;

        if (mode === 'update') {
            // Find existing coverage comment
            const { data: comments } = await octokit.rest.issues.listComments({
                owner,
                repo,
                issue_number: pull_number,
                per_page: 100
            });

            const existingComment = comments.find(comment => 
                comment.body?.includes(COVERAGE_COMMENT_MARKER)
            );

            if (existingComment) {
                // Update existing comment
                await octokit.rest.issues.updateComment({
                    owner,
                    repo,
                    comment_id: existingComment.id,
                    body: md,
                });
                core.info(`Updated existing coverage comment (ID: ${existingComment.id})`);
                return;
            }
        }

        // Create new comment (either mode is 'new' or no existing comment found)
        await octokit.rest.issues.createComment({
            owner,
            repo,
            issue_number: pull_number,
            body: md,
        });
        core.info('Created new coverage comment');

    } catch (error) {
        core.error(`Failed to upsert comment: ${error}`);
        throw error;
    }
}