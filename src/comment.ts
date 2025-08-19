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
    baseRef,
    minThreshold = 50
}: Pick<CommentData, 'totals' | 'baseRef' | 'minThreshold'>): Promise<string> {
    // Generate badges
    const coverageBadge = generateCoverageBadge(totals.totalPct);
    const deltaBadge = totals.deltaPct !== undefined ? generateDeltaBadge(totals.deltaPct) : null;

    // Badge section
    let badgeSection = `[![Coverage](${coverageBadge})](#)`;
    if (deltaBadge) {
        badgeSection += `\n[![Δ vs main](${deltaBadge})](#)`;
    }

    const comparisonText = baseRef ? ` vs ${baseRef}` : '';

    // Summary section
    const thresholdStatus = totals.didBreachThresholds ? '⚠️ **Coverage thresholds not met**' : '✅ **All coverage thresholds met**';
    const summarySection = `## 📊 Coverage Report${comparisonText}

**Overall Coverage**: ${totals.totalPct.toFixed(1)}% (${totals.linesCovered}/${totals.linesTotal} lines)${totals.deltaPct !== undefined ? ` • **Change**: ${totals.deltaPct >= 0 ? '+' : ''}${totals.deltaPct.toFixed(1)}%` : ''}

${thresholdStatus}`;

    // Project Coverage table (collapsible)
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

    // Code Changes Coverage table (not collapsible)
    const changesTable = renderCoverageTable({
        title: 'Code Changes Coverage',
        lineRate: totals.diffPct,
        branchRate: undefined,
        linesHit: totals.diffLinesCovered,
        linesTotal: totals.diffLinesTotal,
        branchesHit: undefined,
        branchesTotal: undefined,
        minThreshold
    });

    return `${COVERAGE_COMMENT_MARKER}
${badgeSection}

${summarySection}

<details>
<summary><b>Project Coverage</b> &nbsp;|&nbsp; <i>expand for full summary</i></summary>

<br/>

${projectTable}

</details>

${changesTable}
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