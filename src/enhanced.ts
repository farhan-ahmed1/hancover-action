import * as core from '@actions/core';
import { readInputs } from './inputs.js';
import { parseAnyCoverage } from './parsers/index.js';
import { groupPackages } from './group.js';
import { computeChangesCoverage, computeDeltaCoverage, parseGitDiff, ChangedLinesByFile } from './changes.js';
import { renderComment, upsertStickyComment } from './comment.js';
import { getCoverageData, saveCoverageData } from './coverage-data.js';
import { execSync } from 'child_process';

export async function runEnhancedCoverage() {
    try {
        const inputs = readInputs();
        
        // Step 1: Parse PR coverage (auto-detect LCOV or Cobertura)
        core.info('Parsing PR coverage...');
        const prFiles = inputs.files;
        
        if (!prFiles || prFiles.length === 0) {
            throw new Error('No coverage files provided');
        }
        
        // For now, use the first coverage file (could be enhanced to merge multiple)
        const prProject = await parseAnyCoverage(prFiles[0]);
        core.info(`Parsed ${prProject.files.length} files from PR coverage`);
        
        // Step 2: Smart package grouping
        const prPackages = groupPackages(prProject.files);
        core.info(`Grouped into ${prPackages.length} packages`);
        
        // Step 3: Get changed lines from git diff
        let changedLinesByFile: ChangedLinesByFile = {};
        try {
            const diffOutput = execSync(
                'git diff --unified=0 --find-renames --diff-filter=AMR origin/main...HEAD',
                { encoding: 'utf8', timeout: 30000 }
            );
            changedLinesByFile = parseGitDiff(diffOutput);
            core.info(`Found changed lines in ${Object.keys(changedLinesByFile).length} files`);
        } catch (error) {
            core.warning(`Failed to get git diff: ${error}`);
        }
        
        // Step 4: Compute code changes coverage
        const changesCoverage = computeChangesCoverage(prProject, changedLinesByFile);
        core.info(`Computed changes coverage for ${changesCoverage.packages.length} packages`);
        
        // Step 5: Parse baseline coverage from gist or baseline files
        let mainBranchCoverage: number | null = null;
        let deltaCoverage;
        
        // First try to get baseline coverage from gist
        core.info('Attempting to fetch baseline coverage from gist...');
        mainBranchCoverage = await getCoverageData(inputs.gistId, inputs.githubToken);
        
        if (mainBranchCoverage !== null) {
            core.info(`✅ Successfully fetched baseline coverage from gist: ${mainBranchCoverage.toFixed(1)}%`);
        } else {
            core.info('❌ No baseline coverage available from gist');
        }
        
        // If no gist coverage available, try baseline files
        if (mainBranchCoverage === null && inputs.baselineFiles && inputs.baselineFiles.length > 0) {
            try {
                core.info('Parsing baseline coverage from files...');
                const mainProject = await parseAnyCoverage(inputs.baselineFiles[0]);
                const mainPackages = groupPackages(mainProject.files);
                
                // Calculate main branch coverage percentage
                mainBranchCoverage = (mainProject.totals.lines.covered / mainProject.totals.lines.total) * 100;
                core.info(`Main branch coverage from files: ${mainBranchCoverage.toFixed(1)}%`);
                
                deltaCoverage = computeDeltaCoverage(prPackages, mainPackages);
                core.info(`Computed delta coverage for ${deltaCoverage.packages.length} packages`);
            } catch (error) {
                core.warning(`Failed to process baseline coverage: ${error}`);
            }
        }
        
        // Step 7: Render the comprehensive comment
        const comment = await renderComment({
            prProject,
            prPackages,
            deltaCoverage,
            mainBranchCoverage,
            minThreshold: inputs.minThreshold
        });
        
        // Step 8: Upsert the comment
        await upsertStickyComment(comment, inputs.commentMode);
        
        // Step 9: Set outputs and check thresholds
        const projectLinesPct = (prProject.totals.lines.covered / prProject.totals.lines.total) * 100;
        const changesLinesPct = changesCoverage.totals.lines.total > 0 
            ? (changesCoverage.totals.lines.covered / changesCoverage.totals.lines.total) * 100 
            : 100;
        
        core.setOutput('coverage-pct', projectLinesPct.toFixed(1));
        core.setOutput('changes-coverage-pct', changesLinesPct.toFixed(1));
        
        // Set coverage delta output if main branch coverage is available
        if (mainBranchCoverage !== null) {
            const coverageDelta = projectLinesPct - mainBranchCoverage;
            core.setOutput('coverage-delta', coverageDelta.toFixed(1));
        }
        
        // Check thresholds
        const thresholdMet = projectLinesPct >= inputs.minThreshold;
        const changesThresholdMet = changesLinesPct >= inputs.minThreshold;
        
        if (!thresholdMet) {
            const message = `Project coverage ${projectLinesPct.toFixed(1)}% is below threshold ${inputs.minThreshold}%`;
            if (inputs.warnOnly) {
                core.warning(message);
            } else {
                core.setFailed(message);
            }
        }
        
        if (!changesThresholdMet && changesCoverage.totals.lines.total > 0) {
            const message = `Changes coverage ${changesLinesPct.toFixed(1)}% is below threshold ${inputs.minThreshold}%`;
            if (inputs.warnOnly) {
                core.warning(message);
            } else {
                core.setFailed(message);
            }
        }
        
        core.info('Enhanced coverage analysis completed successfully');
        
        // Step 10: Save coverage data to gist if we're on main branch
        const isMainBranch = process.env.GITHUB_REF === 'refs/heads/main' || 
                            process.env.GITHUB_REF === 'refs/heads/master';
        
        if (isMainBranch) {
            try {
                await saveCoverageData(projectLinesPct, inputs.gistId, inputs.githubToken);
                core.info(`Saved coverage data to gist for main branch: ${projectLinesPct.toFixed(1)}%`);
            } catch (error) {
                core.warning(`Failed to save coverage data: ${error}`);
            }
        }
        
    } catch (error) {
        core.setFailed(`Enhanced coverage analysis failed: ${error}`);
        throw error;
    }
}
