import * as core from '@actions/core';
import { readInputs } from './inputs.js';
import { parseAnyCoverage } from './parsers/index.js';
import { groupPackages } from './group.js';
import { computeChangesCoverage, computeDeltaCoverage, parseGitDiff, ChangedLinesByFile } from './changes.js';
import { renderComment, upsertStickyComment } from './comment.js';
import { readMainBranchCoverage, writeCoverageData } from './shields.js';
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
        
        // Step 5: Read main branch coverage from local JSON file
        let mainBranchCoverage: number | null = null;
        mainBranchCoverage = readMainBranchCoverage(inputs.coverageDataPath);

        // Step 6: Parse baseline coverage if available (auto-detect format)
        let deltaCoverage;
        if (inputs.baselineFiles && inputs.baselineFiles.length > 0) {
            try {
                core.info('Parsing baseline coverage...');
                const mainProject = await parseAnyCoverage(inputs.baselineFiles[0]);
                const mainPackages = groupPackages(mainProject.files);
                
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
            changesCoverage,
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
        
        // Step 10: Update coverage data file if this is the main branch
        const currentBranch = process.env.GITHUB_REF_NAME || 'unknown';
        const currentCommit = process.env.GITHUB_SHA;
        if (currentBranch === 'main' || currentBranch === 'master') {
            writeCoverageData(inputs.coverageDataPath, projectLinesPct, currentBranch, currentCommit);
            core.info('Updated coverage data file for main branch');
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
        
    } catch (error) {
        core.setFailed(`Enhanced coverage analysis failed: ${error}`);
        throw error;
    }
}
