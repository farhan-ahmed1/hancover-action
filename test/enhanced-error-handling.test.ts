import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';
import {
    parseWithRecovery,
    loadConfigWithRecovery,
    getGitDiffWithRecovery,
    computeChangesCoverageWithRecovery,
    getBaselineCoverageWithRecovery,
    parseBaselineFilesWithRecovery,
    saveGistDataWithRecovery
} from '../src/infrastructure/enhanced-error-handling.js';
import { ErrorAggregator, ErrorCategory } from '../src/infrastructure/error-handling.js';

// Mock all dependencies
vi.mock('@actions/core');
vi.mock('../src/parsers/index.js');
vi.mock('../src/processing/group.js');
vi.mock('../src/processing/changes.js');
vi.mock('../src/io/coverage-data.js');
vi.mock('../src/infrastructure/config.js');
vi.mock('child_process');

const mockInfo = vi.mocked(core.info);
const mockWarning = vi.mocked(core.warning);

// Suppress unused variable warnings for now as these are setup for potential use
void mockInfo;
void mockWarning;

// Import mocked modules
import { parseAnyCoverage } from '../src/parsers/index.js';
import { groupPackages } from '../src/processing/group.js';
import { computeChangesCoverage, computeDeltaCoverage, parseGitDiff } from '../src/processing/changes.js';
import { getCoverageData, saveCoverageData } from '../src/io/coverage-data.js';
import { loadConfig } from '../src/infrastructure/config.js';
import { execSync } from 'child_process';

const mockParseAnyCoverage = vi.mocked(parseAnyCoverage);
const mockGroupPackages = vi.mocked(groupPackages);
const mockComputeChangesCoverage = vi.mocked(computeChangesCoverage);
const mockComputeDeltaCoverage = vi.mocked(computeDeltaCoverage);
const mockParseGitDiff = vi.mocked(parseGitDiff);
const mockGetCoverageData = vi.mocked(getCoverageData);
const mockSaveCoverageData = vi.mocked(saveCoverageData);
const mockLoadConfig = vi.mocked(loadConfig);
const mockExecSync = vi.mocked(execSync);

describe('Enhanced Error Handling Wrappers', () => {
    let aggregator: ErrorAggregator;

    beforeEach(() => {
        vi.clearAllMocks();
        aggregator = new ErrorAggregator();
    });

    // Helper function to create mock project data
    const createMockProject = (overrides: any = {}) => ({
        files: [{
            path: 'src/test.ts',
            lines: { covered: 10, total: 10 },
            branches: { covered: 5, total: 5 },
            functions: { covered: 2, total: 2 },
            coveredLineNumbers: new Set([1, 2, 3]),
            package: 'src'
        }],
        totals: {
            lines: { covered: 10, total: 10 },
            branches: { covered: 5, total: 5 },
            functions: { covered: 2, total: 2 }
        },
        ...overrides
    });

    // Helper function to create mock changes coverage
    const createMockChangesCoverage = (overrides: any = {}) => ({
        packages: [],
        totals: {
            lines: { covered: 5, total: 5 },
            branches: { covered: 3, total: 3 },
            functions: { covered: 1, total: 1 }
        },
        files: [],
        ...overrides
    });

    // Helper function to create mock package data
    const createMockPackages = () => [{
        name: 'src',
        displayName: 'src',
        lines: { covered: 10, total: 10 },
        branches: { covered: 5, total: 5 },
        functions: { covered: 2, total: 2 },
        files: []
    }];

    describe('parseWithRecovery', () => {
        it('should successfully parse coverage file', async () => {
            const mockProject = createMockProject();
            mockParseAnyCoverage.mockResolvedValue(mockProject as any);

            const result = await parseWithRecovery('coverage.xml', {}, aggregator);

            expect(result.success).toBe(true);
            expect(result.data).toBe(mockProject);
            expect(result.errors).toHaveLength(0);
        });

        it('should handle parsing failure with recovery', async () => {
            mockParseAnyCoverage.mockRejectedValue(new Error('Parse failed'));

            const result = await parseWithRecovery('coverage.xml', {}, aggregator);

            expect(result.success).toBe(false);
            expect(result.errors).toHaveLength(1);
            expect(result.errors[0].category).toBe(ErrorCategory.PARSING);
            expect(result.errors[0].message).toContain('Parse failed');
        });

        it('should respect circuit breaker', async () => {
            // Trigger circuit breaker by adding failures
            for (let i = 0; i < 3; i++) {
                aggregator.addError(
                    new (await import('../src/infrastructure/error-handling.js')).ProcessingError(
                        'Test error',
                        (await import('../src/infrastructure/error-handling.js')).ErrorSeverity.RECOVERABLE,
                        ErrorCategory.PARSING,
                        { operation: 'parseAnyCoverage' }
                    )
                );
            }

            const result = await parseWithRecovery('coverage.xml', {}, aggregator);

            expect(result.success).toBe(false);
            expect(result.errors[0].message).toContain('Circuit breaker blocking');
            expect(mockParseAnyCoverage).not.toHaveBeenCalled();
        });
    });

    describe('loadConfigWithRecovery', () => {
        it('should successfully load configuration', async () => {
            const mockConfig = {
                groups: [{ name: 'test', patterns: ['*.ts'] }],
                fallback: { smartDepth: 'auto' as const, promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            };
            mockLoadConfig.mockReturnValue(mockConfig);

            const result = await loadConfigWithRecovery(aggregator);

            expect(result.success).toBe(true);
            expect(result.data).toBe(mockConfig);
        });

        it('should handle config loading failure with fallback', async () => {
            mockLoadConfig.mockImplementation(() => {
                throw new Error('Config load failed');
            });

            const result = await loadConfigWithRecovery(aggregator);

            expect(result.success).toBe(true);
            expect(result.data).toBeDefined();
            expect(result.data.groups).toEqual([]);
            expect(result.warnings).toHaveLength(1);
        });

        it('should use fallback when circuit breaker is open', async () => {
            // Trigger circuit breaker
            for (let i = 0; i < 3; i++) {
                aggregator.addError(
                    new (await import('../src/infrastructure/error-handling.js')).ProcessingError(
                        'Test error',
                        (await import('../src/infrastructure/error-handling.js')).ErrorSeverity.RECOVERABLE,
                        ErrorCategory.CONFIG,
                        { operation: 'loadConfig' }
                    )
                );
            }

            const result = await loadConfigWithRecovery(aggregator);

            expect(result.success).toBe(true);
            expect(result.warnings).toHaveLength(1);
            expect(result.warnings[0].message).toContain('circuit breaker');
            expect(mockLoadConfig).not.toHaveBeenCalled();
        });
    });

    describe('getGitDiffWithRecovery', () => {
        it('should successfully get git diff', async () => {
            const mockDiffOutput = 'diff --git a/file.ts b/file.ts';
            const mockChangedLines = { 'file.ts': new Set([1, 2, 3]) };
            
            mockExecSync.mockReturnValue(mockDiffOutput);
            mockParseGitDiff.mockReturnValue(mockChangedLines);

            const result = await getGitDiffWithRecovery(aggregator);

            expect(result.success).toBe(true);
            expect(result.data).toBe(mockChangedLines);
        });

        it('should handle git diff failure with fallback', async () => {
            mockExecSync.mockImplementation(() => {
                throw new Error('Git command failed');
            });

            const result = await getGitDiffWithRecovery(aggregator);

            expect(result.success).toBe(true);
            expect(result.data).toEqual({});
            expect(result.warnings).toHaveLength(1);
        });
    });

    describe('computeChangesCoverageWithRecovery', () => {
        it('should successfully compute changes coverage', async () => {
            const mockProject = { totals: { lines: { covered: 10, total: 10 } } };
            const mockChangedLines = {};
            const mockPackages = createMockPackages();
            const mockChangesCoverage = createMockChangesCoverage();

            mockComputeChangesCoverage.mockReturnValue(mockChangesCoverage as any);

            const result = await computeChangesCoverageWithRecovery(
                mockProject,
                mockChangedLines,
                mockPackages,
                aggregator
            );

            expect(result.success).toBe(true);
            expect(result.data).toBe(mockChangesCoverage);
        });

        it('should handle computation failure with fallback', async () => {
            const mockProject = { 
                totals: { lines: { covered: 10, total: 10 } }
            };
            const mockChangedLines = {};
            const mockPackages = createMockPackages();

            mockComputeChangesCoverage.mockImplementation(() => {
                throw new Error('Computation failed');
            });

            const result = await computeChangesCoverageWithRecovery(
                mockProject,
                mockChangedLines,
                mockPackages,
                aggregator
            );

            expect(result.success).toBe(true);
            expect(result.data).toEqual({
                packages: mockPackages,
                totals: mockProject.totals,
                files: []
            });
            expect(result.warnings).toHaveLength(1);
        });
    });

    describe('getBaselineCoverageWithRecovery', () => {
        it('should successfully get baseline coverage from gist', async () => {
            const mockCoverage = 85.5;
            mockGetCoverageData.mockResolvedValue(mockCoverage);

            const result = await getBaselineCoverageWithRecovery('gist-id', 'token', aggregator);

            expect(result.success).toBe(true);
            expect(result.data).toBe(mockCoverage);
        });

        it('should handle gist failure with fallback', async () => {
            mockGetCoverageData.mockRejectedValue(new Error('Gist access failed'));

            const result = await getBaselineCoverageWithRecovery('gist-id', 'token', aggregator);

            expect(result.success).toBe(true);
            expect(result.data).toBeNull();
            expect(result.warnings).toHaveLength(1);
        });
    });

    describe('parseBaselineFilesWithRecovery', () => {
        it('should successfully parse baseline files', async () => {
            const mockMainProject = createMockProject({
                totals: { 
                    lines: { covered: 80, total: 100 },
                    branches: { covered: 40, total: 50 },
                    functions: { covered: 8, total: 10 }
                }
            });
            const mockMainPackages = createMockPackages();
            const mockDeltaCoverage = { packages: [] };

            mockParseAnyCoverage.mockResolvedValue(mockMainProject as any);
            mockGroupPackages.mockReturnValue({ pkgRows: mockMainPackages as any, topLevelRows: [] as any });
            mockComputeDeltaCoverage.mockReturnValue(mockDeltaCoverage as any);

            const result = await parseBaselineFilesWithRecovery(
                ['baseline.xml'],
                {},
                aggregator
            );

            expect(result.success).toBe(true);
            expect(result.data).toBeDefined();
            expect(result.data!.mainBranchCoverage).toBe(80);
        });

        it('should handle baseline parsing failure', async () => {
            mockParseAnyCoverage.mockRejectedValue(new Error('Baseline parse failed'));

            const result = await parseBaselineFilesWithRecovery(
                ['baseline.xml'],
                {},
                aggregator
            );

            expect(result.success).toBe(true);
            expect(result.data).toBeNull();
            expect(result.warnings).toHaveLength(1);
        });

        it('should try multiple baseline files', async () => {
            const mockProject = createMockProject({
                totals: { 
                    lines: { covered: 75, total: 100 },
                    branches: { covered: 35, total: 50 },
                    functions: { covered: 7, total: 10 }
                }
            });

            mockParseAnyCoverage
                .mockRejectedValueOnce(new Error('First file failed'))
                .mockResolvedValueOnce(mockProject as any);
            
            mockGroupPackages.mockReturnValue({ pkgRows: [] as any, topLevelRows: [] as any });
            mockComputeDeltaCoverage.mockReturnValue({ packages: [] } as any);

            const result = await parseBaselineFilesWithRecovery(
                ['baseline1.xml', 'baseline2.xml'],
                {},
                aggregator
            );

            expect(result.success).toBe(true);
            expect(result.data!.mainBranchCoverage).toBe(75);
            expect(mockParseAnyCoverage).toHaveBeenCalledTimes(2);
        });
    });

    describe('saveGistDataWithRecovery', () => {
        it('should successfully save gist data', async () => {
            mockSaveCoverageData.mockResolvedValue(undefined);

            const result = await saveGistDataWithRecovery(85.5, 'gist-id', 'token', aggregator);

            expect(result.success).toBe(true);
            expect(mockSaveCoverageData).toHaveBeenCalledWith(85.5, 'gist-id', 'token');
        });

        it('should handle gist save failure with retry', async () => {
            mockSaveCoverageData
                .mockRejectedValueOnce(new Error('Network error'))
                .mockRejectedValueOnce(new Error('Network error'))
                .mockResolvedValue(undefined);

            const result = await saveGistDataWithRecovery(85.5, 'gist-id', 'token', aggregator);

            expect(result.success).toBe(true);
            expect(mockSaveCoverageData).toHaveBeenCalledTimes(3);
        });

        it('should respect circuit breaker', async () => {
            // Trigger circuit breaker
            for (let i = 0; i < 3; i++) {
                aggregator.addError(
                    new (await import('../src/infrastructure/error-handling.js')).ProcessingError(
                        'Test error',
                        (await import('../src/infrastructure/error-handling.js')).ErrorSeverity.RECOVERABLE,
                        ErrorCategory.GIST_OPERATIONS,
                        { operation: 'saveCoverageData' }
                    )
                );
            }

            const result = await saveGistDataWithRecovery(85.5, 'gist-id', 'token', aggregator);

            expect(result.success).toBe(true);
            expect(result.warnings).toHaveLength(1);
            expect(result.warnings[0].message).toContain('circuit breaker');
            expect(mockSaveCoverageData).not.toHaveBeenCalled();
        });
    });

    describe('Integration scenarios', () => {
        it('should handle cascading failures gracefully', async () => {
            // Test scenario where multiple operations fail but system continues
            mockParseAnyCoverage.mockRejectedValue(new Error('Parse failed'));
            mockLoadConfig.mockImplementation(() => { throw new Error('Config failed'); });
            mockExecSync.mockImplementation(() => { throw new Error('Git failed'); });

            // Parse should fail and add error to aggregator
            const parseResult = await parseWithRecovery('coverage.xml', {}, aggregator);
            expect(parseResult.success).toBe(false);
            // The parseWithRecovery should add errors to the aggregator
            parseResult.errors.forEach(e => aggregator.addError(e));

            // Config should provide fallback
            const configResult = await loadConfigWithRecovery(aggregator);
            expect(configResult.success).toBe(true);
            expect(configResult.warnings).toHaveLength(1);

            // Git diff should provide fallback
            const gitResult = await getGitDiffWithRecovery(aggregator);
            expect(gitResult.success).toBe(true);
            expect(gitResult.data).toEqual({});

            // Verify errors were collected
            const summary = aggregator.getSummary();
            expect(summary.totalErrors).toBeGreaterThan(0);
        });

        it('should demonstrate circuit breaker preventing resource waste', async () => {
            // Manually add enough failures to trigger circuit breaker
            for (let i = 0; i < 3; i++) {
                aggregator.addError(
                    new (await import('../src/infrastructure/error-handling.js')).ProcessingError(
                        'Test error',
                        (await import('../src/infrastructure/error-handling.js')).ErrorSeverity.RECOVERABLE,
                        ErrorCategory.PARSING,
                        { operation: 'parseAnyCoverage' }
                    )
                );
            }

            // Reset mock to ensure circuit breaker is preventing calls
            mockParseAnyCoverage.mockClear();

            // This call should be blocked by circuit breaker
            const result = await parseWithRecovery('coverage.xml', {}, aggregator);
            expect(result.success).toBe(false);
            expect(result.errors[0].message).toContain('Circuit breaker blocking');
            expect(mockParseAnyCoverage).not.toHaveBeenCalled();
        });
    });
});
