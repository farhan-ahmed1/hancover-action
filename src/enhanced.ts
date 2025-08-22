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
    
    // Processing results tracker for graceful degradation
    const processingResults = {
        parsed: 0,
        skipped: 0,
        errors: [] as Array<{ file: string; error: string; step: string }>,
        warnings: [] as Array<{ message: string; step: string }>
    };
    
    try {
        inputs = readInputs();
        
        // Step 1: Parse PR coverage with performance enhancements and error recovery
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
        
        // Enhanced parsing with error recovery
        let prProject: any = null;
        for (const file of prFiles) {
            try {
                prProject = await parseAnyCoverage(file, streamingOptions);
                processingResults.parsed++;
                core.info(`✅ Successfully parsed ${file} with ${prProject.files.length} files`);
                break; // Use first successfully parsed file
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                processingResults.errors.push({ 
                    file, 
                    error: errorMessage, 
                    step: 'coverage_parsing' 
                });
                processingResults.skipped++;

                if (inputs.strict) {
                    throw new Error(`Strict mode: Failed to parse coverage file ${file}: ${errorMessage}`);
                } else {
                    core.warning(`Skipping coverage file ${file}: ${errorMessage}`);
                    processingResults.warnings.push({
                        message: `Skipped coverage file ${file}: ${errorMessage}`,
                        step: 'coverage_parsing'
                    });
                }
            }
        }

        // If no files were successfully parsed, fail
        if (!prProject) {
            throw new Error(`Failed to parse any coverage files. Errors: ${processingResults.errors.map(e => `${e.file}: ${e.error}`).join(', ')}`);
        }

        core.info(`✅ Parsed ${prProject.files.length} files from PR coverage`);
        
        // Step 2: Smart package grouping with config support and error recovery
        let config;
        let groupingResult;
        try {
            config = loadConfig();
            groupingResult = groupPackages(prProject.files, config);
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            processingResults.errors.push({ 
                file: 'config', 
                error: errorMessage, 
                step: 'config_loading' 
            });
            
            if (inputs.strict) {
                throw new Error(`Strict mode: Failed to load configuration: ${errorMessage}`);
            } else {
                core.warning(`Failed to load configuration, using fallback: ${errorMessage}`);
                // Use fallback config
                config = {
                    groups: [],
                    fallback: { smartDepth: 'auto' as const, promoteThreshold: 0.8 },
                    ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
                };
                groupingResult = groupPackages(prProject.files, config);
                processingResults.warnings.push({
                    message: `Using fallback configuration due to config error: ${errorMessage}`,
                    step: 'config_loading'
                });
            }
        }
        
        const prPackages = groupingResult.pkgRows;
        const topLevelPackages = groupingResult.topLevelRows;
        
        core.info(`Grouped into ${prPackages.length} detailed packages and ${topLevelPackages.length} top-level packages`);
        
        // Step 3: Get changed lines from git diff with error recovery
        let changedLinesByFile: ChangedLinesByFile = {};
        try {
            const diffOutput = execSync(
                'git diff --unified=0 --find-renames --diff-filter=AMR origin/main...HEAD',
                { encoding: 'utf8', timeout: 30000 }
            );
            changedLinesByFile = parseGitDiff(diffOutput);
            core.info(`Found changed lines in ${Object.keys(changedLinesByFile).length} files`);
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            processingResults.errors.push({ 
                file: 'git_diff', 
                error: errorMessage, 
                step: 'git_diff' 
            });
            
            if (inputs.strict) {
                throw new Error(`Strict mode: Failed to get git diff: ${errorMessage}`);
            } else {
                core.warning(`Failed to get git diff: ${errorMessage}. Proceeding with full coverage analysis.`);
                processingResults.warnings.push({
                    message: `Git diff unavailable, analyzing full coverage: ${errorMessage}`,
                    step: 'git_diff'
                });
            }
        }
        
        // Step 4: Compute code changes coverage with error recovery
        let changesCoverage;
        try {
            changesCoverage = computeChangesCoverage(prProject, changedLinesByFile);
            core.info(`Computed changes coverage for ${changesCoverage.packages.length} packages`);
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            processingResults.errors.push({ 
                file: 'changes_coverage', 
                error: errorMessage, 
                step: 'changes_coverage' 
            });
            
            if (inputs.strict) {
                throw new Error(`Strict mode: Failed to compute changes coverage: ${errorMessage}`);
            } else {
                core.warning(`Failed to compute changes coverage: ${errorMessage}. Using project totals.`);
                // Create fallback changes coverage based on project totals
                changesCoverage = {
                    packages: prPackages,
                    totals: prProject.totals
                };
                processingResults.warnings.push({
                    message: `Using project totals for changes coverage due to error: ${errorMessage}`,
                    step: 'changes_coverage'
                });
            }
        }
        
        // Step 5: Parse baseline coverage from gist or baseline files with error recovery
        let mainBranchCoverage: number | null = null;
        let deltaCoverage;
        
        // First try to get baseline coverage from gist
        try {
            core.info('Attempting to fetch baseline coverage from gist...');
            mainBranchCoverage = await getCoverageData(inputs.gistId, inputs.gistToken);
            
            if (mainBranchCoverage !== null) {
                core.info(`✅ Successfully fetched baseline coverage from gist: ${mainBranchCoverage.toFixed(1)}%`);
            } else {
                core.info('❌ No baseline coverage available from gist');
            }
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            processingResults.errors.push({ 
                file: 'gist_baseline', 
                error: errorMessage, 
                step: 'baseline_gist' 
            });
            
            if (inputs.strict) {
                throw new Error(`Strict mode: Failed to fetch baseline coverage from gist: ${errorMessage}`);
            } else {
                core.warning(`Failed to fetch baseline coverage from gist: ${errorMessage}`);
                processingResults.warnings.push({
                    message: `Gist baseline unavailable: ${errorMessage}`,
                    step: 'baseline_gist'
                });
            }
        }
        
        // If no gist coverage available, try baseline files
        if (mainBranchCoverage === null && inputs.baselineFiles && inputs.baselineFiles.length > 0) {
            for (const baselineFile of inputs.baselineFiles) {
                try {
                    core.info(`Parsing baseline coverage from file: ${baselineFile}...`);
                    const mainProject = await parseAnyCoverage(baselineFile);
                    const mainGroupingResult = groupPackages(mainProject.files, config);
                    const mainPackages = mainGroupingResult.pkgRows;
                    
                    // Calculate main branch coverage percentage
                    mainBranchCoverage = (mainProject.totals.lines.covered / mainProject.totals.lines.total) * 100;
                    core.info(`Main branch coverage from file ${baselineFile}: ${mainBranchCoverage.toFixed(1)}%`);
                    
                    deltaCoverage = computeDeltaCoverage(prPackages, mainPackages);
                    core.info(`Computed delta coverage for ${deltaCoverage.packages.length} packages`);
                    break; // Use first successful baseline
                } catch (error) {
                    const errorMessage = error instanceof Error ? error.message : String(error);
                    processingResults.errors.push({ 
                        file: baselineFile, 
                        error: errorMessage, 
                        step: 'baseline_files' 
                    });
                    
                    if (inputs.strict) {
                        throw new Error(`Strict mode: Failed to process baseline coverage file ${baselineFile}: ${errorMessage}`);
                    } else {
                        core.warning(`Failed to process baseline coverage file ${baselineFile}: ${errorMessage}`);
                        processingResults.warnings.push({
                            message: `Skipped baseline file ${baselineFile}: ${errorMessage}`,
                            step: 'baseline_files'
                        });
                    }
                }
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
        
        // Log processing results summary
        if (processingResults.warnings.length > 0 || processingResults.errors.length > 0) {
            core.info(`Processing Summary: ${processingResults.parsed} parsed, ${processingResults.skipped} skipped, ${processingResults.warnings.length} warnings, ${processingResults.errors.length} errors`);
            
            if (processingResults.warnings.length > 0) {
                core.info('Warnings encountered:');
                processingResults.warnings.forEach(w => core.warning(`[${w.step}] ${w.message}`));
            }
            
            if (processingResults.errors.length > 0 && !inputs.strict) {
                core.info('Errors handled gracefully (non-strict mode):');
                processingResults.errors.forEach(e => core.info(`[${e.step}] ${e.file}: ${e.error}`));
            }
        }
        
        // Step 10: Save coverage data to gist if we're on main branch
        const isMainBranch = process.env.GITHUB_REF === 'refs/heads/main' || 
                            process.env.GITHUB_REF === 'refs/heads/master';
        
        if (isMainBranch) {
            try {
                await saveCoverageData(projectLinesPct, inputs.gistId, inputs.gistToken);
                core.info(`Saved coverage data to gist for main branch: ${projectLinesPct.toFixed(1)}%`);
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                processingResults.errors.push({ 
                    file: 'gist_save', 
                    error: errorMessage, 
                    step: 'gist_save' 
                });
                
                if (inputs.strict) {
                    throw new Error(`Strict mode: Failed to save coverage data: ${errorMessage}`);
                } else {
                    core.warning(`Failed to save coverage data: ${errorMessage}`);
                }
            }
        }
        
        // Ensure clean exit by explicitly terminating any lingering processes
        // This prevents hanging when there are uncleared timeouts or event listeners
        // Only exit forcefully in production GitHub Actions environment
        const isTestEnvironment = process.env.NODE_ENV === 'test' || 
                                 process.env.VITEST === 'true' || 
                                 process.env.JEST_WORKER_ID !== undefined ||
                                 typeof (globalThis as any).it === 'function';
        
        if (!isTestEnvironment) {
            process.nextTick(() => {
                process.exit(0);
            });
        }
        
    } catch (error) {
        // Enhanced error context with detailed diagnostic information
        const context = {
            files: inputs?.files || [],
            totalSize: inputs?.files ? getTotalFileSize(inputs.files) : 0,
            timeElapsed: Date.now() - startTime,
            processingResults: {
                parsed: processingResults.parsed,
                skipped: processingResults.skipped,
                errorsCount: processingResults.errors.length,
                warningsCount: processingResults.warnings.length,
                errors: processingResults.errors,
                warnings: processingResults.warnings
            }
        };
        
        const errorMessage = error instanceof Error ? error.message : String(error);
        const contextString = JSON.stringify(context, null, 2);
        
        // Log processing summary even on failure
        if (processingResults.errors.length > 0 || processingResults.warnings.length > 0) {
            core.error(`Final processing state: ${processingResults.parsed} parsed, ${processingResults.skipped} skipped, ${processingResults.warnings.length} warnings, ${processingResults.errors.length} errors`);
        }
        
        core.setFailed(`Coverage processing failed: ${errorMessage}\nContext: ${contextString}`);
        
        // Ensure process exits even on failure to prevent hanging
        // Only exit forcefully in production GitHub Actions environment
        const isTestEnvironment = process.env.NODE_ENV === 'test' || 
                                 process.env.VITEST === 'true' || 
                                 process.env.JEST_WORKER_ID !== undefined ||
                                 typeof (globalThis as any).it === 'function';
        
        if (!isTestEnvironment) {
            process.nextTick(() => {
                process.exit(1);
            });
        }
        
        throw error;
    }
}
