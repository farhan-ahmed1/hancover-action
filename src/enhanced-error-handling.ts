/**
 * Enhanced error handling wrapper functions for coverage processing operations
 * Provides comprehensive error recovery and circuit breaker patterns for the enhanced coverage system
 */

import * as core from '@actions/core';
import { parseAnyCoverage } from './parsers/index.js';
import { groupPackages } from './group.js';
import { computeChangesCoverage, computeDeltaCoverage, parseGitDiff, ChangedLinesByFile } from './changes.js';
import { getCoverageData, saveCoverageData } from './coverage-data.js';
import { loadConfig } from './config.js';
import { execSync } from 'child_process';
import * as fs from 'fs';
import {
    ProcessingResult,
    ProcessingError,
    ProcessingWarning,
    ErrorCategory,
    ErrorAggregator,
    ErrorHandlingUtils
} from './error-handling.js';

/**
 * Enhanced error handling for coverage file parsing
 */
async function parseWithRecovery(file: string, options: any, aggregator: ErrorAggregator): Promise<ProcessingResult<any>> {
    const context = ErrorHandlingUtils.createContext('parseAnyCoverage', file, 'coverage_parsing');
    
    // Check circuit breaker
    if (aggregator.shouldBlock(ErrorCategory.PARSING, 'parseAnyCoverage')) {
        return ProcessingResult.failure(
            ProcessingError.recoverable(
                'Circuit breaker blocking parsing operations',
                ErrorCategory.PARSING,
                context
            )
        );
    }

    return ErrorHandlingUtils.withErrorHandling(
        () => parseAnyCoverage(file, options),
        context,
        ErrorCategory.PARSING,
        { retryCount: 1, strict: false }
    );
}

/**
 * Enhanced error handling for configuration loading
 */
async function loadConfigWithRecovery(aggregator: ErrorAggregator): Promise<ProcessingResult<any>> {
    const context = ErrorHandlingUtils.createContext('loadConfig', undefined, 'config_loading');
    
    if (aggregator.shouldBlock(ErrorCategory.CONFIG, 'loadConfig')) {
        // Return fallback config when circuit breaker is open
        const fallbackConfig = {
            groups: [],
            fallback: { smartDepth: 'auto' as const, promoteThreshold: 0.8 },
            ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
        };
        
        const warning: ProcessingWarning = {
            message: 'Using fallback configuration due to circuit breaker',
            category: ErrorCategory.CONFIG,
            context,
            timestamp: new Date()
        };
        
        return ProcessingResult.partial(fallbackConfig, [warning]);
    }

    return ErrorHandlingUtils.withErrorHandling(
        () => Promise.resolve(loadConfig()),
        context,
        ErrorCategory.CONFIG,
        {
            strict: false,
            fallback: {
                groups: [],
                fallback: { smartDepth: 'auto' as const, promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            }
        }
    );
}

/**
 * Enhanced error handling for git diff operations
 */
async function getGitDiffWithRecovery(aggregator: ErrorAggregator): Promise<ProcessingResult<ChangedLinesByFile>> {
    const context = ErrorHandlingUtils.createContext('execSync', 'git diff', 'git_diff');
    
    if (aggregator.shouldBlock(ErrorCategory.GIT_DIFF, 'execSync')) {
        const warning: ProcessingWarning = {
            message: 'Git diff unavailable due to circuit breaker, using empty change set',
            category: ErrorCategory.GIT_DIFF,
            context,
            timestamp: new Date()
        };
        return ProcessingResult.partial({}, [warning]);
    }

    return ErrorHandlingUtils.withErrorHandling(
        () => {
            const diffOutput = execSync(
                'git diff --unified=0 --find-renames --diff-filter=AMR origin/main...HEAD',
                { encoding: 'utf8', timeout: 30000 }
            );
            return Promise.resolve(parseGitDiff(diffOutput));
        },
        context,
        ErrorCategory.GIT_DIFF,
        { strict: false, fallback: {} }
    );
}

/**
 * Enhanced error handling for changes coverage computation
 */
async function computeChangesCoverageWithRecovery(
    prProject: any,
    changedLinesByFile: ChangedLinesByFile,
    prPackages: any[],
    aggregator: ErrorAggregator
): Promise<ProcessingResult<any>> {
    const context = ErrorHandlingUtils.createContext('computeChangesCoverage', undefined, 'changes_coverage');
    
    if (aggregator.shouldBlock(ErrorCategory.CHANGES_COVERAGE, 'computeChangesCoverage')) {
        // Fallback to project totals
        const fallback = {
            packages: prPackages,
            totals: prProject.totals,
            files: []
        };
        
        const warning: ProcessingWarning = {
            message: 'Using project totals for changes coverage due to circuit breaker',
            category: ErrorCategory.CHANGES_COVERAGE,
            context,
            timestamp: new Date()
        };
        
        return ProcessingResult.partial(fallback, [warning]);
    }

    return ErrorHandlingUtils.withErrorHandling(
        () => Promise.resolve(computeChangesCoverage(prProject, changedLinesByFile)),
        context,
        ErrorCategory.CHANGES_COVERAGE,
        {
            strict: false,
            fallback: {
                packages: prPackages,
                totals: prProject.totals,
                files: []
            }
        }
    );
}

/**
 * Enhanced error handling for baseline coverage retrieval
 */
async function getBaselineCoverageWithRecovery(
    gistId?: string,
    gistToken?: string,
    aggregator?: ErrorAggregator
): Promise<ProcessingResult<number | null>> {
    const context = ErrorHandlingUtils.createContext('getCoverageData', gistId, 'baseline_gist');
    
    if (aggregator?.shouldBlock(ErrorCategory.GIST_OPERATIONS, 'getCoverageData')) {
        const warning: ProcessingWarning = {
            message: 'Baseline coverage unavailable due to circuit breaker',
            category: ErrorCategory.GIST_OPERATIONS,
            context,
            timestamp: new Date()
        };
        return ProcessingResult.partial(null, [warning]);
    }

    return ErrorHandlingUtils.withErrorHandling(
        () => getCoverageData(gistId, gistToken),
        context,
        ErrorCategory.GIST_OPERATIONS,
        { strict: false, fallback: null }
    );
}

/**
 * Enhanced error handling for baseline file parsing
 */
async function parseBaselineFilesWithRecovery(
    baselineFiles: string[],
    config: any,
    aggregator: ErrorAggregator
): Promise<ProcessingResult<{ mainBranchCoverage: number; deltaCoverage: any } | null>> {
    for (const baselineFile of baselineFiles) {
        const context = ErrorHandlingUtils.createContext('parseAnyCoverage', baselineFile, 'baseline_files');
        
        if (aggregator.shouldBlock(ErrorCategory.PARSING, 'parseAnyCoverage')) {
            continue; // Skip this file and try the next one
        }

        const result = await ErrorHandlingUtils.withErrorHandling(
            async () => {
                const mainProject = await parseAnyCoverage(baselineFile);
                const mainGroupingResult = groupPackages(mainProject.files, config);
                const mainPackages = mainGroupingResult.pkgRows;
                
                const mainBranchCoverage = (mainProject.totals.lines.covered / mainProject.totals.lines.total) * 100;
                const deltaCoverage = computeDeltaCoverage([], mainPackages); // This needs to be passed the prPackages
                
                return { mainBranchCoverage, deltaCoverage };
            },
            context,
            ErrorCategory.PARSING
        );

        if (result.success && result.data) {
            aggregator.recordSuccess(ErrorCategory.PARSING, 'parseAnyCoverage');
            return result;
        } else {
            // Add the error to aggregator and try next file
            if (result.errors.length > 0) {
                result.errors.forEach(e => aggregator.addError(e));
            }
        }
    }

    // No baseline files could be parsed
    const warning: ProcessingWarning = {
        message: 'No baseline files could be parsed',
        category: ErrorCategory.PARSING,
        context: ErrorHandlingUtils.createContext('parseBaselineFiles', baselineFiles.join(', '), 'baseline_files'),
        timestamp: new Date()
    };
    
    return ProcessingResult.partial(null, [warning]);
}

/**
 * Enhanced error handling for gist operations
 */
async function saveGistDataWithRecovery(
    projectLinesPct: number,
    gistId?: string,
    gistToken?: string,
    aggregator?: ErrorAggregator
): Promise<ProcessingResult<void>> {
    const context = ErrorHandlingUtils.createContext('saveCoverageData', gistId, 'gist_save');
    
    if (aggregator?.shouldBlock(ErrorCategory.GIST_OPERATIONS, 'saveCoverageData')) {
        const warning: ProcessingWarning = {
            message: 'Gist save operation blocked by circuit breaker',
            category: ErrorCategory.GIST_OPERATIONS,
            context,
            timestamp: new Date()
        };
        return ProcessingResult.partial(undefined, [warning]);
    }

    return ErrorHandlingUtils.withErrorHandling(
        () => saveCoverageData(projectLinesPct, gistId, gistToken),
        context,
        ErrorCategory.GIST_OPERATIONS,
        { retryCount: 2, strict: false }
    );
}

/**
 * Calculate total size of all provided files with error handling
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

export {
    parseWithRecovery,
    loadConfigWithRecovery,
    getGitDiffWithRecovery,
    computeChangesCoverageWithRecovery,
    getBaselineCoverageWithRecovery,
    parseBaselineFilesWithRecovery,
    saveGistDataWithRecovery,
    getTotalFileSize
};
