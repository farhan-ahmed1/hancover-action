import * as core from '@actions/core';
import { readInputs } from '../io/inputs.js';
import { groupPackages } from '../processing/group.js';
import { computeDeltaCoverage } from '../processing/changes.js';
import { renderComment, upsertStickyComment } from '../output/comment.js';
import {
    parseWithRecovery,
    loadConfigWithRecovery,
    getGitDiffWithRecovery,
    computeChangesCoverageWithRecovery,
    getBaselineCoverageWithRecovery,
    parseBaselineFilesWithRecovery,
    saveGistDataWithRecovery,
    getTotalFileSize
} from '../infrastructure/enhanced-error-handling.js';
import {
    ErrorAggregator,
    ErrorCategory
} from '../infrastructure/error-handling.js';
import { logger } from '../infrastructure/logger.js';
import { performanceMonitor } from '../infrastructure/performance-monitor.js';
import { validateInputs } from '../infrastructure/input-validator.js';

/**
 * Enhanced coverage analysis with comprehensive error handling and graceful degradation
 */
export async function runEnhancedCoverage() {
    const startTime = Date.now();
    let inputs: ReturnType<typeof readInputs> | undefined;
    
    // Initialize error aggregator for centralized error tracking
    const errorAggregator = new ErrorAggregator();
    const executionContext = logger.createContext('enhanced-coverage-analysis', { 
        startTime 
    });
    
    try {
        inputs = readInputs();
        
        // Enhanced input validation with detailed error messages
        logger.info('Validating input configuration...', executionContext);
        const validationResult = validateInputs({
            files: inputs.files,
            thresholds: inputs.thresholds,
            groups: inputs.groups ? JSON.stringify(inputs.groups) : undefined,
            timeoutSeconds: inputs.timeoutSeconds,
            maxBytesPerFile: inputs.maxBytesPerFile,
            maxTotalBytes: inputs.maxTotalBytes,
            gistId: inputs.gistId,
            gistToken: inputs.gistToken
        });

        if (!validationResult.success) {
            const errorMessage = `Input validation failed:\n${validationResult.errors.map(e => 
                `- ${e.field}: ${e.message}${e.suggestion ? ` (Suggestion: ${e.suggestion})` : ''}`
            ).join('\n')}`;
            
            if (inputs.strict) {
                throw new Error(errorMessage);
            } else {
                core.warning(errorMessage);
            }
        }

        if (validationResult.warnings.length > 0) {
            const warningMessage = `Input validation warnings:\n${validationResult.warnings.map(w => 
                `- ${w.field}: ${w.message}${w.suggestion ? ` (Suggestion: ${w.suggestion})` : ''}`
            ).join('\n')}`;
            core.warning(warningMessage);
        }
        
        // Step 1: Parse PR coverage with enhanced error recovery
        logger.info('Starting enhanced coverage analysis with comprehensive error handling...', executionContext);
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

        logger.info(`Processing ${prFiles.length} coverage file(s) with timeout: ${inputs.timeoutSeconds}s`, executionContext);
        
        // Enhanced parsing with circuit breaker and retry logic
        let prProject: any = null;
        
        // Use performance monitor to track parsing operations
        prProject = await performanceMonitor.measure('parse-coverage-files', async () => {
            for (const file of prFiles) {
                const parseResult = await parseWithRecovery(file, streamingOptions, errorAggregator);
                
                if (parseResult.success && parseResult.data) {
                    errorAggregator.recordSuccess(ErrorCategory.PARSING, 'parseAnyCoverage');
                    logger.info(`Successfully parsed ${file} with ${parseResult.data.files.length} files`, executionContext);
                    return parseResult.data; // Return first successfully parsed file
                } else {
                    // Collect errors and warnings
                    parseResult.errors.forEach(e => errorAggregator.addError(e));
                    parseResult.warnings.forEach(w => errorAggregator.addWarning(w));
                    
                    if (inputs?.strict && parseResult.hasFatalErrors()) {
                        throw new Error(`Strict mode: Failed to parse coverage file ${file}: ${parseResult.getErrorMessages().join(', ')}`);
                    }
                }
            }
            return null;
        }, { fileCount: prFiles.length });

        // If no files were successfully parsed, fail appropriately
        if (!prProject) {
            const errorMessage = `Failed to parse any coverage files. Attempted ${prFiles.length} files.`;
            if (inputs.strict) {
                throw new Error(errorMessage);
            } else {
                // In non-strict mode, we can't continue without any coverage data
                core.setFailed(errorMessage);
                errorAggregator.logSummary();
                return;
            }
        }

        core.info(`✅ Parsed ${prProject.files.length} files from PR coverage`);
        
        // Step 2: Smart package grouping with enhanced error recovery
        const configResult = await loadConfigWithRecovery(errorAggregator);
        let config;
        
        if (configResult.success && configResult.data) {
            config = configResult.data;
            errorAggregator.recordSuccess(ErrorCategory.CONFIG, 'loadConfig');
        } else {
            configResult.errors.forEach(e => errorAggregator.addError(e));
            configResult.warnings.forEach(w => errorAggregator.addWarning(w));
            
            if (inputs.strict && configResult.hasFatalErrors()) {
                throw new Error(`Strict mode: Failed to load configuration: ${configResult.getErrorMessages().join(', ')}`);
            }
            
            // Use the fallback config from the result
            config = configResult.data;
        }
        
        const groupingResult = groupPackages(prProject.files, config);
        const prPackages = groupingResult.pkgRows;
        const topLevelPackages = groupingResult.topLevelRows;
        
        core.info(`Grouped into ${prPackages.length} detailed packages and ${topLevelPackages.length} top-level packages`);
        
        // Step 3: Get changed lines from git diff with enhanced error recovery
        const gitDiffResult = await getGitDiffWithRecovery(errorAggregator);
        let changedLinesByFile = {};
        
        if (gitDiffResult.success && gitDiffResult.data) {
            changedLinesByFile = gitDiffResult.data;
            errorAggregator.recordSuccess(ErrorCategory.GIT_DIFF, 'execSync');
            core.info(`Found changed lines in ${Object.keys(changedLinesByFile).length} files`);
        } else {
            gitDiffResult.errors.forEach(e => errorAggregator.addError(e));
            gitDiffResult.warnings.forEach(w => errorAggregator.addWarning(w));
            
            if (inputs.strict && gitDiffResult.hasFatalErrors()) {
                throw new Error(`Strict mode: Failed to get git diff: ${gitDiffResult.getErrorMessages().join(', ')}`);
            }
            
            // Use empty change set as fallback
            changedLinesByFile = gitDiffResult.data || {};
        }
        
        // Step 4: Compute code changes coverage with enhanced error recovery
        const changesCoverageResult = await computeChangesCoverageWithRecovery(
            prProject,
            changedLinesByFile,
            prPackages,
            errorAggregator
        );
        
        let changesCoverage;
        if (changesCoverageResult.success && changesCoverageResult.data) {
            changesCoverage = changesCoverageResult.data;
            errorAggregator.recordSuccess(ErrorCategory.CHANGES_COVERAGE, 'computeChangesCoverage');
            core.info(`Computed changes coverage for ${changesCoverage.packages.length} packages`);
        } else {
            changesCoverageResult.errors.forEach(e => errorAggregator.addError(e));
            changesCoverageResult.warnings.forEach(w => errorAggregator.addWarning(w));
            
            if (inputs.strict && changesCoverageResult.hasFatalErrors()) {
                throw new Error(`Strict mode: Failed to compute changes coverage: ${changesCoverageResult.getErrorMessages().join(', ')}`);
            }
            
            // Use fallback from result
            changesCoverage = changesCoverageResult.data;
        }
        
        // Step 5: Parse baseline coverage with enhanced error recovery
        let mainBranchCoverage: number | null = null;
        let deltaCoverage;
        
        // First try to get baseline coverage from gist
        const gistResult = await getBaselineCoverageWithRecovery(inputs.gistId, inputs.gistToken, errorAggregator);
        
        if (gistResult.success && gistResult.data !== null && gistResult.data !== undefined) {
            mainBranchCoverage = gistResult.data;
            errorAggregator.recordSuccess(ErrorCategory.GIST_OPERATIONS, 'getCoverageData');
            core.info(`✅ Successfully fetched baseline coverage from gist: ${mainBranchCoverage.toFixed(1)}%`);
        } else {
            gistResult.errors.forEach(e => errorAggregator.addError(e));
            gistResult.warnings.forEach(w => errorAggregator.addWarning(w));
            
            if (inputs.strict && gistResult.hasFatalErrors()) {
                throw new Error(`Strict mode: Failed to fetch baseline coverage from gist: ${gistResult.getErrorMessages().join(', ')}`);
            }
            
            core.info('❌ No baseline coverage available from gist');
        }
        
        // If no gist coverage available, try baseline files
        if (mainBranchCoverage === null && inputs.baselineFiles && inputs.baselineFiles.length > 0) {
            const baselineResult = await parseBaselineFilesWithRecovery(inputs.baselineFiles, config, errorAggregator);
            
            if (baselineResult.success && baselineResult.data) {
                mainBranchCoverage = baselineResult.data.mainBranchCoverage;
                deltaCoverage = computeDeltaCoverage(prPackages, baselineResult.data.deltaCoverage);
                core.info(`Main branch coverage from baseline files: ${mainBranchCoverage.toFixed(1)}%`);
                core.info(`Computed delta coverage for ${deltaCoverage.packages.length} packages`);
            } else {
                baselineResult.errors.forEach(e => errorAggregator.addError(e));
                baselineResult.warnings.forEach(w => errorAggregator.addWarning(w));
                
                if (inputs.strict && baselineResult.hasFatalErrors()) {
                    throw new Error(`Strict mode: Failed to process baseline coverage files: ${baselineResult.getErrorMessages().join(', ')}`);
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
        
        // Step 10: Save coverage data to gist if we're on main branch
        const isMainBranch = process.env.GITHUB_REF === 'refs/heads/main' || 
                            process.env.GITHUB_REF === 'refs/heads/master';
        
        if (isMainBranch) {
            const saveResult = await saveGistDataWithRecovery(projectLinesPct, inputs.gistId, inputs.gistToken, errorAggregator);
            
            if (saveResult.success) {
                errorAggregator.recordSuccess(ErrorCategory.GIST_OPERATIONS, 'saveCoverageData');
                core.info(`Saved coverage data to gist for main branch: ${projectLinesPct.toFixed(1)}%`);
            } else {
                saveResult.errors.forEach(e => errorAggregator.addError(e));
                saveResult.warnings.forEach(w => errorAggregator.addWarning(w));
                
                if (inputs.strict && saveResult.hasFatalErrors()) {
                    throw new Error(`Strict mode: Failed to save coverage data: ${saveResult.getErrorMessages().join(', ')}`);
                }
            }
        }
        
        // Log comprehensive summary including performance metrics
        logger.info('Enhanced coverage analysis completed successfully', executionContext);
        performanceMonitor.logSummary();
        errorAggregator.logSummary();
        
        // Ensure clean exit by explicitly terminating any lingering processes
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
            aggregatorSummary: errorAggregator.getSummary()
        };
        
        const errorMessage = error instanceof Error ? error.message : String(error);
        const contextString = JSON.stringify(context, null, 2);
        
        // Log final error aggregator state
        core.error('Final error state:');
        errorAggregator.logSummary();
        
        core.setFailed(`Coverage processing failed: ${errorMessage}\nContext: ${contextString}`);
        
        // Ensure process exits even on failure to prevent hanging
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
