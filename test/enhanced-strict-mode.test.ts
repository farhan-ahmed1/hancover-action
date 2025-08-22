import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as core from '@actions/core';
import { runEnhancedCoverage } from '../src/enhanced-v2.js';

// Mock all dependencies
vi.mock('@actions/core');
vi.mock('child_process');
vi.mock('fs');
vi.mock('../src/inputs.js');
vi.mock('../src/parsers/index.js');
vi.mock('../src/group.js');
vi.mock('../src/changes.js');
vi.mock('../src/comment.js');
vi.mock('../src/coverage-data.js');
vi.mock('../src/config.js');

const mockInfo = vi.mocked(core.info);
const mockWarning = vi.mocked(core.warning);

// Import mocked modules
import * as childProcess from 'child_process';
import * as configModule from '../src/config.js';
import * as inputsModule from '../src/inputs.js';
import * as parsersModule from '../src/parsers/index.js';
import * as commentModule from '../src/comment.js';
import * as coverageDataModule from '../src/coverage-data.js';
import * as changesModule from '../src/changes.js';
import { groupPackages } from '../src/group.js';

const mockExecSync = vi.mocked(childProcess.execSync);
const mockLoadConfig = vi.mocked(configModule.loadConfig);
const mockReadInputs = vi.mocked(inputsModule.readInputs);
const mockParseAnyCoverage = vi.mocked(parsersModule.parseAnyCoverage);
const mockRenderComment = vi.mocked(commentModule.renderComment);
const mockUpsertStickyComment = vi.mocked(commentModule.upsertStickyComment);
const mockGetCoverageData = vi.mocked(coverageDataModule.getCoverageData);
const mockSaveCoverageData = vi.mocked(coverageDataModule.saveCoverageData);
const mockComputeChangesCoverage = vi.mocked(changesModule.computeChangesCoverage);
const mockParseGitDiff = vi.mocked(changesModule.parseGitDiff);

describe('Enhanced Coverage - Strict Mode & Error Handling', () => {
    let mockProcessExit: any;

    beforeEach(() => {
        vi.clearAllMocks();
        delete process.env.GITHUB_REF;
        // Ensure we're detected as a test environment
        process.env.NODE_ENV = 'test';
        process.env.VITEST = 'true';
        // Set up global test function detection
        (globalThis as any).it = it;
        
        // Mock process.exit to prevent actual exits during testing
        mockProcessExit = vi.spyOn(process, 'exit').mockImplementation(() => {
            throw new Error('process.exit called');
        });
    });

    afterEach(() => {
        vi.resetAllMocks();
        // Restore process.exit
        mockProcessExit?.mockRestore();
    });

    describe('Strict Mode Error Handling', () => {
        const createMockInputsStrict = (overrides = {}) => ({
            files: ['coverage/lcov.info'],
            baselineFiles: [],
            minThreshold: 50,
            warnOnly: false,
            commentMode: 'update' as const,
            gistId: '',
            gistToken: '',
            strict: true, // Enable strict mode
            timeoutSeconds: 120,
            ...overrides
        });

        it('should fail in strict mode when config loading fails', async () => {
            mockReadInputs.mockReturnValue(createMockInputsStrict() as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            // Mock config loading to fail
            mockLoadConfig.mockImplementation(() => {
                throw new Error('Failed to load configuration');
            });

            await expect(runEnhancedCoverage()).rejects.toThrow('Strict mode: Failed to load configuration: Failed to load configuration');
        });

        it('should fail in strict mode when changes coverage computation fails', async () => {
            mockReadInputs.mockReturnValue(createMockInputsStrict() as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            // Mock config
            mockLoadConfig.mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            });

            // Mock grouping
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }],
                topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }]
            });

            // Mock git diff
            mockExecSync.mockReturnValue('diff --git a/src/example.ts b/src/example.ts\n@@ -1,0 +2,1 @@\n+test');
            mockParseGitDiff.mockReturnValue({ 'src/example.ts': new Set([2]) });

            // Mock changes coverage to fail
            mockComputeChangesCoverage.mockImplementation(() => {
                throw new Error('Failed to compute changes coverage');
            });

            await expect(runEnhancedCoverage()).rejects.toThrow('Strict mode: Failed to compute changes coverage: Failed to compute changes coverage');
        });

        it('should fail in strict mode when git diff fails', async () => {
            mockReadInputs.mockReturnValue(createMockInputsStrict() as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            // Mock config
            mockLoadConfig.mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            });

            // Mock grouping
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }],
                topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }]
            });

            // Mock git diff to fail
            mockExecSync.mockImplementation(() => {
                throw new Error('Git command failed');
            });

            await expect(runEnhancedCoverage()).rejects.toThrow('Strict mode: Failed to get git diff: Git command failed');
        });

        it('should fail in strict mode when gist baseline fetching fails', async () => {
            mockReadInputs.mockReturnValue(createMockInputsStrict({
                gistId: 'test-gist',
                gistToken: 'test-token'
            }) as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            // Mock config
            mockLoadConfig.mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            });

            // Mock grouping
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }],
                topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }]
            });

            // Mock git diff
            mockExecSync.mockReturnValue('');
            mockParseGitDiff.mockReturnValue({});
            mockComputeChangesCoverage.mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            // Mock gist to fail
            mockGetCoverageData.mockRejectedValue(new Error('Failed to fetch from gist'));

            await expect(runEnhancedCoverage()).rejects.toThrow('Strict mode: Failed to fetch baseline coverage from gist: Failed to fetch from gist');
        });

        it('should fail in strict mode when baseline file processing fails', async () => {
            mockReadInputs.mockReturnValue(createMockInputsStrict({
                baselineFiles: ['baseline.lcov']
            }) as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValueOnce(mockProject).mockRejectedValueOnce(new Error('Failed to parse baseline file'));

            // Mock config
            mockLoadConfig.mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            });

            // Mock grouping
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }],
                topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }]
            });

            // Mock git diff
            mockExecSync.mockReturnValue('');
            mockParseGitDiff.mockReturnValue({});
            mockComputeChangesCoverage.mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            // Mock gist to return null
            mockGetCoverageData.mockResolvedValue(null);

            await expect(runEnhancedCoverage()).rejects.toThrow('Strict mode: Failed to process baseline coverage file baseline.lcov: Failed to parse baseline file');
        });

        it('should fail in strict mode when saving coverage data fails on main branch', async () => {
            process.env.GITHUB_REF = 'refs/heads/main';

            mockReadInputs.mockReturnValue(createMockInputsStrict({
                gistId: 'test-gist',
                gistToken: 'test-token'
            }) as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            // Mock config
            mockLoadConfig.mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            });

            // Mock grouping
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }],
                topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }]
            });

            // Mock git diff
            mockExecSync.mockReturnValue('');
            mockParseGitDiff.mockReturnValue({});
            mockComputeChangesCoverage.mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            // Mock gist
            mockGetCoverageData.mockResolvedValue(null);
            mockSaveCoverageData.mockRejectedValue(new Error('Failed to save to gist'));

            // Mock comment rendering
            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await expect(runEnhancedCoverage()).rejects.toThrow('Strict mode: Failed to save coverage data: Failed to save to gist');
        });

        it('should fail in strict mode when coverage file parsing fails', async () => {
            mockReadInputs.mockReturnValue(createMockInputsStrict() as any);

            // Mock parseAnyCoverage to fail for all files
            mockParseAnyCoverage.mockRejectedValue(new Error('Parse failed'));

            await expect(runEnhancedCoverage()).rejects.toThrow('Strict mode: Failed to parse coverage file coverage/lcov.info: Parse failed');
        });
    });

    describe('Additional Error Handling Coverage', () => {
        it('should handle non-strict mode gracefully for changes coverage computation errors', async () => {
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: '',
                gistToken: '',
                strict: false, // Non-strict mode
                timeoutSeconds: 120
            } as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            // Mock config
            mockLoadConfig.mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            });

            // Mock grouping
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }],
                topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }]
            });

            // Mock git diff
            mockExecSync.mockReturnValue('diff --git a/src/example.ts b/src/example.ts\n@@ -1,0 +2,1 @@\n+test');
            mockParseGitDiff.mockReturnValue({ 'src/example.ts': new Set([2]) });

            // Mock changes coverage to fail
            mockComputeChangesCoverage.mockImplementation(() => {
                throw new Error('Changes coverage computation failed');
            });

            // Mock gist
            mockGetCoverageData.mockResolvedValue(null);

            // Mock comment rendering
            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockWarning).toHaveBeenCalledWith('Failed to compute changes coverage: Changes coverage computation failed. Using project totals.');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });

        it('should handle non-strict mode gracefully for gist baseline fetching errors', async () => {
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: 'test-gist',
                gistToken: 'test-token',
                strict: false, // Non-strict mode
                timeoutSeconds: 120
            } as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            // Mock config
            mockLoadConfig.mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            });

            // Mock grouping
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }],
                topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }]
            });

            // Mock git diff
            mockExecSync.mockReturnValue('');
            mockParseGitDiff.mockReturnValue({});
            mockComputeChangesCoverage.mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            // Mock gist to fail
            mockGetCoverageData.mockRejectedValue(new Error('Gist API failed'));

            // Mock comment rendering
            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockWarning).toHaveBeenCalledWith('Failed to fetch baseline coverage from gist: Gist API failed');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });

        it('should handle non-strict mode gracefully for baseline file processing errors', async () => {
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: ['baseline1.lcov', 'baseline2.lcov'],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: '',
                gistToken: '',
                strict: false, // Non-strict mode
                timeoutSeconds: 120
            } as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };

            // Mock first file success, second file fails, third file fails
            mockParseAnyCoverage.mockResolvedValueOnce(mockProject)
                .mockRejectedValueOnce(new Error('Failed to parse baseline1'))
                .mockRejectedValueOnce(new Error('Failed to parse baseline2'));

            // Mock config
            mockLoadConfig.mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            });

            // Mock grouping
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }],
                topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }]
            });

            // Mock git diff
            mockExecSync.mockReturnValue('');
            mockParseGitDiff.mockReturnValue({});
            mockComputeChangesCoverage.mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            // Mock gist to return null
            mockGetCoverageData.mockResolvedValue(null);

            // Mock comment rendering
            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockWarning).toHaveBeenCalledWith('Failed to process baseline coverage file baseline1.lcov: Failed to parse baseline1');
            expect(mockWarning).toHaveBeenCalledWith('Failed to process baseline coverage file baseline2.lcov: Failed to parse baseline2');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });

        it('should handle non-strict mode gracefully for config loading errors', async () => {
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: '',
                gistToken: '',
                strict: false, // Non-strict mode
                timeoutSeconds: 120
            } as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            // Mock config loading to fail
            mockLoadConfig.mockImplementation(() => {
                throw new Error('Config file corrupted');
            });

            // Mock grouping with fallback config
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }],
                topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }]
            });

            // Mock git diff
            mockExecSync.mockReturnValue('');
            mockParseGitDiff.mockReturnValue({});
            mockComputeChangesCoverage.mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            // Mock gist
            mockGetCoverageData.mockResolvedValue(null);

            // Mock comment rendering
            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockWarning).toHaveBeenCalledWith('Failed to load configuration, using fallback: Config file corrupted');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });
    });
});
