import * as core from '@actions/core';
import { readInputs } from './inputs.js';
import { parseAnyCoverage } from './parsers/index.js';
import { groupPackages } from './group.js';
import { computeChangesCoverage, computeDeltaCoverage, parseGitDiff, ChangedLinesByFile } from './changes.js';
import { renderComment, upsertStickyComment } from './comment.js';
import { getCoverageData, saveCoverageData } from './coverage-data.js';
import { loadConfig } from './config.js';
import { execSync } from 'child_process';
import * as fs from 'fs';

/**
 * Calculate total size of all provided files
 */
function getTotalFileSize(filePaths: string[]): number {
    let totalSize = 0;
    for (const filePath of filePaths) {
        try {
            const stats = fs.statSync(filePath);
            totalSize += stats.size;
        } catch (error) {
            // File might not exist or be accessible, continue
            core.debug(`Could not get size for file ${filePath}: ${error}`);
        }
    }
    return totalSize;
}

export async function runEnhancedCoverage() {
    const startTime = Date.now();
    let inputs: ReturnType<typeof readInputs> | undefined;
    
    try {
        inputs = readInputs();
        
        // Step 1: Parse PR coverage with performance enhancements
        core.info('🚀 Starting enhanced coverage analysis with performance optimizations...');
        const prFiles = inputs.files;
        
        if (!prFiles || prFiles.length === 0) {
            throw new Error('No coverage files provided');
        }

        // Configure streaming options based on input timeouts
        const streamingOptions = {
            timeoutMs: inputs.timeoutSeconds * 1000,
            maxMemoryUsage: 10 * 1024 * 1024, // 10MB threshold for streaming
            chunkSize: 64 * 1024 // 64KB chunks
        };

        core.info(`Processing ${prFiles.length} coverage file(s) with timeout: ${inputs.timeoutSeconds}s`);
        
        // For now, use the first coverage file (could be enhanced to merge multiple)
        const prProject = await parseAnyCoverage(prFiles[0], streamingOptions);
        core.info(`✅ Parsed ${prProject.files.length} files from PR coverage`);
        
        // Step 2: Smart package grouping with config support
        const config = loadConfig();
        const groupingResult = groupPackages(prProject.files, config);
        const prPackages = groupingResult.pkgRows;
        const topLevelPackages = groupingResult.topLevelRows;
        
        core.info(`Grouped into ${prPackages.length} detailed packages and ${topLevelPackages.length} top-level packages`);
        
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
        mainBranchCoverage = await getCoverageData(inputs.gistId, inputs.gistToken);
        
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
                const mainGroupingResult = groupPackages(mainProject.files, config);
                const mainPackages = mainGroupingResult.pkgRows;
                
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
            topLevelPackages,
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
                await saveCoverageData(projectLinesPct, inputs.gistId, inputs.gistToken);
                core.info(`Saved coverage data to gist for main branch: ${projectLinesPct.toFixed(1)}%`);
            } catch (error) {
                core.warning(`Failed to save coverage data: ${error}`);
            }
        }
        
    } catch (error) {
        // Enhanced error context with detailed diagnostic information
        const context = {
            files: inputs?.files || [],
            totalSize: inputs?.files ? getTotalFileSize(inputs.files) : 0,
            timeElapsed: Date.now() - startTime
        };
        
        const errorMessage = error instanceof Error ? error.message : String(error);
        const contextString = JSON.stringify(context, null, 2);
        
        core.setFailed(`Coverage processing failed: ${errorMessage}\nContext: ${contextString}`);
        throw error;
    }
}
