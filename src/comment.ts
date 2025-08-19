import * as core from '@actions/core';
import * as github from '@actions/github';
import { ProjectCov, PkgCov } from './schema.js';
import { ChangesCoverage, DeltaCoverage } from './changes.js';
import { pct } from './group.js';
import { getHealthIcon } from './badges.js';

const COVERAGE_COMMENT_MARKER = '<!-- coverage-comment:anchor -->';

export interface CommentData {
    prProject: ProjectCov;
    prPackages: PkgCov[];
    changesCoverage: ChangesCoverage;
    deltaCoverage?: DeltaCoverage;
    minThreshold?: number;
}

export async function renderComment(data: CommentData): Promise<string> {
    const { prProject, prPackages, changesCoverage, deltaCoverage, minThreshold = 50 } = data;
    
    // Generate badges
    const projectLinesPct = pct(prProject.totals.lines.covered, prProject.totals.lines.total);
    const coverageBadge = shield('coverage', `${projectLinesPct.toFixed(1)}%`, colorForPct(projectLinesPct));
    
    let deltaBadge = '';
    if (deltaCoverage && deltaCoverage.packages.length > 0) {
        // Calculate overall delta from summary
        const totalDelta = calculateOverallDelta(deltaCoverage);
        deltaBadge = `\n[![Δ vs main](${shield('Δ coverage', formatDelta(totalDelta), deltaColor(totalDelta))})](#)`;
    }
    
    // Badge section
    const badgeSection = `[![Coverage](${coverageBadge})](#)${deltaBadge}`;
    
    // Generate table sections
    const projectTable = renderProjectTable(prPackages, minThreshold);
    const changesTable = renderChangesTable(changesCoverage, minThreshold);
    const deltaTable = deltaCoverage ? renderDeltaTable(deltaCoverage, minThreshold) : '';
    
    return `${COVERAGE_COMMENT_MARKER}
${badgeSection}

<details>
<summary><b>Code Coverage</b> — click to expand</summary>

<br/>

### Project Coverage (PR)
${projectTable}

---

### Code Changes Coverage
${changesTable}

${deltaTable ? `---\n\n${deltaTable}` : ''}

</details>
`;
}

function renderProjectTable(packages: PkgCov[], minThreshold: number): string {
    if (packages.length === 0) {
        return '_No coverage data available_';
    }
    
    let table = `| Package | Statements | Branches | Functions | Health |
|---|---:|---:|---:|:---:|
`;
    
    // Package rows
    for (const pkg of packages) {
        const linesPct = pct(pkg.totals.lines.covered, pkg.totals.lines.total);
        const branchesPct = pct(pkg.totals.branches.covered, pkg.totals.branches.total);
        const functionsPct = pct(pkg.totals.functions.covered, pkg.totals.functions.total);
        const health = getHealthIcon(linesPct, minThreshold);
        
        table += `| ${pkg.name} | ${linesPct.toFixed(1)}% (${pkg.totals.lines.covered}/${pkg.totals.lines.total}) | ${branchesPct.toFixed(1)}% (${pkg.totals.branches.covered}/${pkg.totals.branches.total}) | ${functionsPct.toFixed(1)}% (${pkg.totals.functions.covered}/${pkg.totals.functions.total}) | ${health} |\n`;
    }
    
    // Summary row
    const totalLines = packages.reduce((sum, pkg) => sum + pkg.totals.lines.total, 0);
    const totalLinesCovered = packages.reduce((sum, pkg) => sum + pkg.totals.lines.covered, 0);
    const totalBranches = packages.reduce((sum, pkg) => sum + pkg.totals.branches.total, 0);
    const totalBranchesCovered = packages.reduce((sum, pkg) => sum + pkg.totals.branches.covered, 0);
    const totalFunctions = packages.reduce((sum, pkg) => sum + pkg.totals.functions.total, 0);
    const totalFunctionsCovered = packages.reduce((sum, pkg) => sum + pkg.totals.functions.covered, 0);
    
    const summaryLinesPct = pct(totalLinesCovered, totalLines);
    const summaryBranchesPct = pct(totalBranchesCovered, totalBranches);
    const summaryFunctionsPct = pct(totalFunctionsCovered, totalFunctions);
    const summaryHealth = getHealthIcon(summaryLinesPct, minThreshold);
    
    table += `| **Summary** | **${summaryLinesPct.toFixed(1)}% (${totalLinesCovered}/${totalLines})** | **${summaryBranchesPct.toFixed(1)}% (${totalBranchesCovered}/${totalBranches})** | **${summaryFunctionsPct.toFixed(1)}% (${totalFunctionsCovered}/${totalFunctions})** | **${summaryHealth}** |\n`;
    
    table += `\n_Minimum pass threshold is ${minThreshold.toFixed(1)}%_`;
    
    return table;
}

function renderChangesTable(changesCoverage: ChangesCoverage, minThreshold: number): string {
    if (changesCoverage.packages.length === 0) {
        return '_No code changes detected_';
    }
    
    let table = `| Package | Statements | Health |
|---|---:|:---:|
`;
    
    // Package rows
    for (const pkg of changesCoverage.packages) {
        const linesPct = pct(pkg.totals.lines.covered, pkg.totals.lines.total);
        const health = getHealthIcon(linesPct, minThreshold);
        
        table += `| ${pkg.name} | ${linesPct.toFixed(1)}% (${pkg.totals.lines.covered}/${pkg.totals.lines.total}) | ${health} |\n`;
    }
    
    // Summary row
    const summaryLinesPct = pct(changesCoverage.totals.lines.covered, changesCoverage.totals.lines.total);
    const summaryHealth = getHealthIcon(summaryLinesPct, minThreshold);
    
    table += `| **Summary** | **${summaryLinesPct.toFixed(1)}% (${changesCoverage.totals.lines.covered}/${changesCoverage.totals.lines.total})** | **${summaryHealth}** |\n`;
    
    table += `\n_Minimum pass threshold is ${minThreshold.toFixed(1)}%_`;
    
    return table;
}

function renderDeltaTable(deltaCoverage: DeltaCoverage, minThreshold: number): string {
    if (deltaCoverage.packages.length === 0) {
        return '';
    }
    
    // Show top 10 packages by absolute delta
    const top10 = deltaCoverage.packages.slice(0, 10);
    const remaining = deltaCoverage.packages.slice(10);
    
    let table = `### Coverage Delta (PR vs main)
| Package | Statements | Branches | Functions | Health |
|---|---:|---:|---:|:---:|
`;
    
    // Top 10 rows
    for (const pkg of top10) {
        const health = getHealthIcon(pkg.linesDeltas.pr, minThreshold);
        
        table += `| ${pkg.name} | ${pkg.linesDeltas.pr.toFixed(1)}% (${formatDelta(pkg.linesDeltas.delta)}) | ${pkg.branchesDeltas.pr.toFixed(1)}% (${formatDelta(pkg.branchesDeltas.delta)}) | ${pkg.functionsDeltas.pr.toFixed(1)}% (${formatDelta(pkg.functionsDeltas.delta)}) | ${health} |\n`;
    }
    
    // Calculate summary delta
    const totalDelta = calculateOverallDelta(deltaCoverage);
    const summaryHealth = getHealthIcon(calculateOverallPct(deltaCoverage), minThreshold);
    
    table += `| **Summary** | **${calculateOverallPct(deltaCoverage).toFixed(1)}% (${formatDelta(totalDelta)})** | **—** | **—** | **${summaryHealth}** |\n`;
    
    // Add collapsed section for remaining packages if any
    if (remaining.length > 0) {
        table += `\n<details>
<summary><i>Show ${remaining.length} more packages...</i></summary>

| Package | Statements | Branches | Functions | Health |
|---|---:|---:|---:|:---:|
`;
        
        for (const pkg of remaining) {
            const health = getHealthIcon(pkg.linesDeltas.pr, minThreshold);
            
            table += `| ${pkg.name} | ${pkg.linesDeltas.pr.toFixed(1)}% (${formatDelta(pkg.linesDeltas.delta)}) | ${pkg.branchesDeltas.pr.toFixed(1)}% (${formatDelta(pkg.branchesDeltas.delta)}) | ${pkg.functionsDeltas.pr.toFixed(1)}% (${formatDelta(pkg.functionsDeltas.delta)}) | ${health} |\n`;
        }
        
        table += '\n</details>';
    }
    
    return table;
}

function calculateOverallDelta(deltaCoverage: DeltaCoverage): number {
    if (deltaCoverage.packages.length === 0) return 0;
    
    // Simple average of deltas (could be weighted by file count)
    const totalDelta = deltaCoverage.packages.reduce((sum, pkg) => sum + pkg.linesDeltas.delta, 0);
    return totalDelta / deltaCoverage.packages.length;
}

function calculateOverallPct(deltaCoverage: DeltaCoverage): number {
    if (deltaCoverage.packages.length === 0) return 0;
    
    // Simple average of PR percentages (could be weighted by file count)
    const totalPct = deltaCoverage.packages.reduce((sum, pkg) => sum + pkg.linesDeltas.pr, 0);
    return totalPct / deltaCoverage.packages.length;
}

function formatDelta(delta: number): string {
    if (delta === 0) return '±0.0%';
    return `${delta >= 0 ? '+' : ''}${delta.toFixed(1)}%`;
}

function shield(label: string, value: string, color: string): string {
    const e = encodeURIComponent;
    return `https://img.shields.io/badge/${e(label)}-${e(value)}-${e(color)}`;
}

function colorForPct(p: number): string {
    return p >= 90 ? 'brightgreen' : p >= 80 ? 'green' : p >= 70 ? 'yellowgreen' : p >= 60 ? 'yellow' : p >= 50 ? 'orange' : 'red';
}

function deltaColor(d: number): string { 
    return d >= 0 ? 'brightgreen' : 'red'; 
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