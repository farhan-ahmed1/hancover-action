import * as core from '@actions/core';
import * as github from '@actions/github';
import { Totals } from './compute.js';
import { GroupSummary } from './group.js';

const STICKY_COMMENT_MARKER = '<!-- hancover:sticky -->';

export async function renderComment({ 
    totals, 
    grouped, 
    thresholds,
    baseRef 
}: { 
    totals: Totals; 
    grouped?: GroupSummary[]; 
    thresholds?: any;
    baseRef?: string;
}): Promise<string> {
    const groupsMd = grouped && grouped.length > 0 
        ? grouped.map(g => `- **${g.name}**: ${g.coveragePct.toFixed(1)}% (${g.linesCovered}/${g.linesTotal} lines)`).join('\n')
        : 'No groups found.';

    const thresholdStatus = totals.didBreachThresholds ? '❌' : '✅';
    const comparisonText = baseRef ? ` vs ${baseRef}` : '';

    return `${STICKY_COMMENT_MARKER}

## 📊 Coverage Report${comparisonText}

### Overall Coverage ${thresholdStatus}

| Metric | Coverage | Status |
|--------|----------|--------|
| **Total Coverage** | ${totals.totalPct.toFixed(1)}% | ${totals.totalPct >= 80 ? '✅' : '⚠️'} |
| **Diff Coverage** | ${totals.diffPct.toFixed(1)}% | ${totals.diffPct >= 80 ? '✅' : '⚠️'} |
| **Branch Coverage** | ${totals.branchPct != null ? totals.branchPct.toFixed(1) + '%' : 'N/A'} | ${totals.branchPct != null && totals.branchPct >= 80 ? '✅' : '⚠️'} |

### 📈 Coverage by Group

${groupsMd}

### 📋 Summary

- **Lines Covered**: ${totals.linesCovered}/${totals.linesTotal}
- **Changed Lines Covered**: ${totals.diffLinesCovered}/${totals.diffLinesTotal}
- **Thresholds**: ${thresholds ? JSON.stringify(thresholds, null, 2) : 'Not configured'}

${totals.didBreachThresholds ? '⚠️ **Coverage thresholds not met**' : '✅ **All coverage thresholds met**'}
`;
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
            // Find existing sticky comment
            const { data: comments } = await octokit.rest.issues.listComments({
                owner,
                repo,
                issue_number: pull_number,
            });

            const existingComment = comments.find(comment => 
                comment.body?.includes(STICKY_COMMENT_MARKER)
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