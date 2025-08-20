import * as core from '@actions/core';
import * as github from '@actions/github';
import { ProjectCov, PkgCov } from './schema.js';
import { DeltaCoverage } from './changes.js';
import { pct } from './group.js';
import { getHealthIcon } from './badges.js';
import { loadConfig } from './config.js';

const COVERAGE_COMMENT_MARKER = '<!-- coverage-comment:anchor -->';

export interface CommentData {
    prProject: ProjectCov;
    prPackages: PkgCov[];
    topLevelPackages?: PkgCov[];  // New: top-level summary
    deltaCoverage?: DeltaCoverage;
    mainBranchCoverage?: number | null;
    minThreshold?: number;
}

export async function renderComment(data: CommentData): Promise<string> {
    const { prProject, prPackages, topLevelPackages, deltaCoverage, mainBranchCoverage, minThreshold = 50 } = data;
    const config = loadConfig();
    
    // Generate badges
    const projectLinesPct = pct(prProject.totals.lines.covered, prProject.totals.lines.total);
    const coverageBadge = shield('coverage', `${projectLinesPct.toFixed(1)}%`, colorForPct(projectLinesPct));
    
    // Generate changes badge if main branch coverage is available
    let changesBadge = '';
    core.info(`Checking for changes badge: mainBranchCoverage = ${mainBranchCoverage}`);
    
    if (mainBranchCoverage !== null && mainBranchCoverage !== undefined) {
        const delta = projectLinesPct - mainBranchCoverage;
        let value: string;
        if (delta >= 0) {
            value = `+${delta.toFixed(1)}%`;
        } else {
            // Use Unicode minus sign (−) instead of hyphen-minus (-) to avoid separator conflicts
            value = `−${Math.abs(delta).toFixed(1)}%`;
        }
        const color = delta >= 0 ? 'brightgreen' : 'red';
        changesBadge = ` [![Changes](${shield('changes', value, color)})](#)`;
        core.info(`✅ Generated changes badge: ${value} (${projectLinesPct.toFixed(1)}% - ${mainBranchCoverage.toFixed(1)}%)`);
    } else {
        core.info('❌ No changes badge - missing baseline coverage data');
    }
    
    let deltaBadge = '';
    if (deltaCoverage && deltaCoverage.packages.length > 0) {
        // Calculate overall delta from summary
        const totalDelta = calculateOverallDelta(deltaCoverage);
        deltaBadge = ` [![Δ vs main](${shield('Δ coverage', formatDelta(totalDelta), deltaColor(totalDelta))})](#)`;
    }
    
    // Badge section
    const badgeSection = `[![Coverage](${coverageBadge})](#)${changesBadge}${deltaBadge}`;
    
    // Generate table sections
    const topLevelTable = topLevelPackages ? renderTopLevelSummaryTable(topLevelPackages, minThreshold) : '';
    const projectTable = renderProjectTable(prPackages, minThreshold, config);
    const deltaTable = deltaCoverage ? renderDeltaTable(deltaCoverage, minThreshold) : '';
    
    // Calculate overall coverage for display
    const overallCoverage = `**Overall Coverage:** ${projectLinesPct.toFixed(1)}%`;
    const totalLines = prPackages.reduce((sum, pkg) => sum + pkg.totals.lines.total, 0);
    const totalLinesCovered = prPackages.reduce((sum, pkg) => sum + pkg.totals.lines.covered, 0);
    const coverageStats = `**Lines Covered:** ${totalLinesCovered}/${totalLines}`;
    
    // Generate coverage change sentence if main branch coverage is available
    let coverageChangeSentence = '';
    if (mainBranchCoverage !== null && mainBranchCoverage !== undefined) {
        const delta = projectLinesPct - mainBranchCoverage;
        if (delta > 0) {
            coverageChangeSentence = `\n\n_Changes made in this PR increased coverage by ${delta.toFixed(1)} percentage points._`;
        } else if (delta < 0) {
            coverageChangeSentence = `\n\n_Changes made in this PR decreased coverage by ${Math.abs(delta).toFixed(1)} percentage points._`;
        } else {
            coverageChangeSentence = '\n\n_Changes made in this PR did not affect overall coverage._';
        }
    }
    
    return `${COVERAGE_COMMENT_MARKER}
## Coverage Report
<!-- Last updated: ${new Date().toISOString()} -->

${badgeSection}

${overallCoverage} | ${coverageStats}${coverageChangeSentence}

${topLevelTable ? `${topLevelTable}\n` : ''}

<details>
<summary><b>Detailed Coverage by Package</b></summary>

<br/>

${projectTable}

</details>

${deltaTable ? `\n${deltaTable}` : ''}

_Minimum pass threshold is ${minThreshold.toFixed(1)}%_
`;
}

function renderTopLevelSummaryTable(packages: PkgCov[], minThreshold: number): string {
    if (packages.length === 0) {
        return '';
    }
    
    let table = `### Top-level Packages (Summary)

| Package | Statements | Branches | Functions | Health |
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
    
    // Only add summary row if there are multiple top-level packages
    if (packages.length > 1) {
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
    }
    
    return table;
}

function renderProjectTable(packages: PkgCov[], minThreshold: number, config?: any): string {
    if (packages.length === 0) {
        return '_No coverage data available_';
    }
    
    const resolvedConfig = config || loadConfig();
    
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
    
    // Add expandable file tables after the main table
    let expandableTables = '';
    for (const pkg of packages) {
        const shouldExpand = shouldExpandPackage(pkg, resolvedConfig);
        if (shouldExpand) {
            expandableTables += renderExpandableFileTable(pkg, minThreshold);
        }
    }
    
    return table + expandableTables;
}

/**
 * Determine if a package should have an expandable file table
 */
function shouldExpandPackage(pkg: PkgCov, config: any): boolean {
    // Check explicit config first
    if (config?.ui?.expandFilesFor?.includes(pkg.name)) {
        return true;
    }
    
    // Default: expand packages with >= 2 files but not too many (to avoid spam)
    return pkg.files.length >= 2 && pkg.files.length <= 20;
}

/**
 * Render an expandable <details> block with file-level coverage
 */
function renderExpandableFileTable(pkg: PkgCov, minThreshold: number): string {
    if (pkg.files.length <= 1) {
        return '';
    }
    
    let fileTable = `
<details>
<summary><b>Files in <code>${pkg.name}</code></b></summary>

| File | Statements | Branches | Functions | Health |
|---|---:|---:|---:|:---:|
`;
    
    // Sort files by name for consistent ordering
    const sortedFiles = [...pkg.files].sort((a, b) => a.path.localeCompare(b.path));
    
    for (const file of sortedFiles) {
        const linesPct = pct(file.lines.covered, file.lines.total);
        const branchesPct = pct(file.branches.covered, file.branches.total);
        const functionsPct = pct(file.functions.covered, file.functions.total);
        const health = getHealthIcon(linesPct, minThreshold);
        
        fileTable += `| ${file.path} | ${linesPct.toFixed(1)}% (${file.lines.covered}/${file.lines.total}) | ${branchesPct.toFixed(1)}% (${file.branches.covered}/${file.branches.total}) | ${functionsPct.toFixed(1)}% (${file.functions.covered}/${file.functions.total}) | ${health} |\n`;
    }
    
    // Add package total row
    const linesPct = pct(pkg.totals.lines.covered, pkg.totals.lines.total);
    const branchesPct = pct(pkg.totals.branches.covered, pkg.totals.branches.total);
    const functionsPct = pct(pkg.totals.functions.covered, pkg.totals.functions.total);
    const health = getHealthIcon(linesPct, minThreshold);
    
    fileTable += `| **Total** | **${linesPct.toFixed(1)}% (${pkg.totals.lines.covered}/${pkg.totals.lines.total})** | **${branchesPct.toFixed(1)}% (${pkg.totals.branches.covered}/${pkg.totals.branches.total})** | **${functionsPct.toFixed(1)}% (${pkg.totals.functions.covered}/${pkg.totals.functions.total})** | **${health}** |

</details>
`;
    
    return fileTable;
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
    return `https://img.shields.io/badge/${e(label)}-${e(value)}-${color}`;
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

            const coverageComments = comments.filter(comment => {
                const body = comment.body || '';
                return body.includes(COVERAGE_COMMENT_MARKER) || body.includes('## Coverage Report');
            });
            
            if (coverageComments.length > 1) {
                core.warning(`Found multiple coverage comments (${coverageComments.length}), using the latest one`);
            }

            const existingComment = coverageComments[coverageComments.length - 1]; // Use the latest one

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