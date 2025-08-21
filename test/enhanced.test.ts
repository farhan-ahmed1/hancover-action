import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as core from '@actions/core';
import { parseLCOV } from '../src/parsers/lcov.js';
import { groupPackages } from '../src/group.js';
import { computeChangesCoverage, parseGitDiff } from '../src/changes.js';
import { renderComment } from '../src/comment.js';
import { runEnhancedCoverage } from '../src/enhanced.js';

// Mock all dependencies for runEnhancedCoverage tests
vi.mock('@actions/core');
vi.mock('child_process');
vi.mock('../src/inputs.js');
vi.mock('../src/parsers/index.js');
vi.mock('../src/group.js');
vi.mock('../src/changes.js');
vi.mock('../src/comment.js');
vi.mock('../src/coverage-data.js');
vi.mock('../src/config.js');

const mockSetOutput = vi.mocked(core.setOutput);
const mockSetFailed = vi.mocked(core.setFailed);
const mockInfo = vi.mocked(core.info);
const mockWarning = vi.mocked(core.warning);

// Import and mock at top level to ensure proper mocking
import * as childProcess from 'child_process';
import * as configModule from '../src/config.js';
import * as inputsModule from '../src/inputs.js';
import * as parsersModule from '../src/parsers/index.js';
import * as commentModule from '../src/comment.js';
import * as coverageDataModule from '../src/coverage-data.js';

const mockExecSync = vi.mocked(childProcess.execSync);
const mockLoadConfig = vi.mocked(configModule.loadConfig);
const mockReadInputs = vi.mocked(inputsModule.readInputs);
const mockParseAnyCoverage = vi.mocked(parsersModule.parseAnyCoverage);
const mockRenderComment = vi.mocked(commentModule.renderComment);
const mockUpsertStickyComment = vi.mocked(commentModule.upsertStickyComment);
const mockGetCoverageData = vi.mocked(coverageDataModule.getCoverageData);
const mockSaveCoverageData = vi.mocked(coverageDataModule.saveCoverageData);

describe('Enhanced Coverage System', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    test('can parse LCOV and create comment', async () => {
        // Don't mock these for the integration test
        vi.doUnmock('../src/group.js');
        vi.doUnmock('../src/changes.js');
        vi.doUnmock('../src/comment.js');
        vi.doUnmock('../src/config.js');
        
        // Re-import after unmocking
        const { groupPackages: realGroupPackages } = await import('../src/group.js');
        const { computeChangesCoverage: realComputeChangesCoverage } = await import('../src/changes.js');
        const { renderComment: realRenderComment } = await import('../src/comment.js');
        const sampleLcov = `TN:
SF:src/example.ts
FN:1,exampleFunction
FNDA:5,exampleFunction
FNF:1
FNH:1
DA:1,5
DA:2,3
DA:3,0
LF:3
LH:2
BRF:0
BRH:0
end_of_record
`;

        const project = parseLCOV(sampleLcov);
        expect(project.files).toHaveLength(1);
        expect(project.files[0].path).toBe('src/example.ts');
        expect(project.files[0].lines.covered).toBe(2);
        expect(project.files[0].lines.total).toBe(3);
        expect(project.files[0].functions.covered).toBe(1);
        expect(project.files[0].functions.total).toBe(1);

        const groupingResult = realGroupPackages(project.files);
        const packages = groupingResult.pkgRows;
        expect(packages).toHaveLength(1);
        expect(packages[0].name).toBe('src');

        const changesCoverage = realComputeChangesCoverage(project, {
            'src/example.ts': new Set([1, 2])
        });

        expect(changesCoverage.totals.lines.covered).toBe(2);
        expect(changesCoverage.totals.lines.total).toBe(2);

        const comment = await realRenderComment({
            prProject: project,
            prPackages: packages,
            minThreshold: 50
        });

        expect(comment).toContain('Coverage Report');
        expect(comment).toContain('Detailed Coverage by Package');
    });

    test('can parse git diff', async () => {
        // Don't mock parseGitDiff for this test
        vi.doUnmock('../src/changes.js');
        
        const { parseGitDiff: realParseGitDiff } = await import('../src/changes.js');
        const gitDiff = `diff --git a/src/file1.ts b/src/file1.ts
index abc123..def456 100644
--- a/src/file1.ts
+++ b/src/file1.ts
@@ -10,0 +11,3 @@ export function example() {
+  const newLine1 = true;
+  const newLine2 = false;
+  return newLine1 && newLine2;
`;

        const result = realParseGitDiff(gitDiff);
        expect(result['src/file1.ts']).toEqual(new Set([11, 12, 13]));
    });

    describe('runEnhancedCoverage', () => {
        beforeEach(() => {
            vi.clearAllMocks();
            delete process.env.GITHUB_REF;
        });

        afterEach(() => {
            vi.resetAllMocks();
        });

        it('should run enhanced coverage analysis successfully', async () => {
            // Mock inputs
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: '',
                gistToken: ''
            } as any);

            // Mock coverage parsing
            const mockProject = {
                files: [
                    {
                        path: 'src/example.ts',
                        lines: { covered: 85, total: 100 },
                        branches: { covered: 40, total: 50 },
                        functions: { covered: 8, total: 10 },
                        coveredLineNumbers: new Set([1, 2, 3]),
                        package: 'src'
                    }
                ],
                totals: {
                    lines: { covered: 85, total: 100 },
                    branches: { covered: 40, total: 50 },
                    functions: { covered: 8, total: 10 }
                }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            // Mock grouping
            vi.mocked(groupPackages).mockReturnValue({
                pkgRows: [
                    {
                        name: 'src',
                        files: mockProject.files,
                        totals: mockProject.totals
                    }
                ],
                topLevelRows: [
                    {
                        name: 'src',
                        files: mockProject.files,
                        totals: mockProject.totals
                    }
                ]
            });

            // Mock config
            mockLoadConfig.mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 }
            });

            // Mock git diff
            mockExecSync.mockReturnValue('diff --git a/src/example.ts b/src/example.ts\n@@ -1,0 +2,1 @@\n+test');

            // Mock git diff parsing and changes coverage
            vi.mocked(parseGitDiff).mockReturnValue({ 'src/example.ts': new Set([2]) });
            vi.mocked(computeChangesCoverage).mockReturnValue({
                files: [],
                packages: [],
                totals: { lines: { covered: 1, total: 1 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            // Mock coverage data
            mockGetCoverageData.mockResolvedValue(null);

            // Mock comment rendering
            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockInfo).toHaveBeenCalledWith('Parsing PR coverage...');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
            expect(mockSetOutput).toHaveBeenCalledWith('coverage-pct', '85.0');
            expect(mockSetOutput).toHaveBeenCalledWith('changes-coverage-pct', '100.0');
            expect(mockSetFailed).not.toHaveBeenCalled();
        });

        it('should handle missing coverage files', async () => {
            mockReadInputs.mockReturnValue({
                files: [],
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: '',
                gistToken: ''
            } as any);

            await expect(runEnhancedCoverage()).rejects.toThrow();
            expect(mockSetFailed).toHaveBeenCalledWith('Enhanced coverage analysis failed: Error: No coverage files provided');
        });

        it('should handle git diff errors gracefully', async () => {
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: '',
                gistToken: ''
            } as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            vi.mocked(groupPackages).mockReturnValue({ pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }], topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }] });

            mockLoadConfig.mockReturnValue({ groups: [], fallback: { smartDepth: 'auto', promoteThreshold: 0.8 }, ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 } });

            // Mock git diff to throw error
            mockExecSync.mockImplementation(() => {
                throw new Error('Git diff failed');
            });

            vi.mocked(parseGitDiff).mockReturnValue({});
            vi.mocked(computeChangesCoverage).mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            mockGetCoverageData.mockResolvedValue(null);

            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockWarning).toHaveBeenCalledWith('Failed to get git diff: Error: Git diff failed');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });

        it('should save coverage data on main branch', async () => {
            // Set to main branch
            process.env.GITHUB_REF = 'refs/heads/main';

            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: 'test-gist',
                gistToken: 'test-token'
            } as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 40, total: 50 }, functions: { covered: 8, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            vi.mocked(groupPackages).mockReturnValue({ pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }], topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }] });

            mockLoadConfig.mockReturnValue({ groups: [], fallback: { smartDepth: 'auto', promoteThreshold: 0.8 }, ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 } });

            mockExecSync.mockReturnValue('');

            vi.mocked(parseGitDiff).mockReturnValue({});
            vi.mocked(computeChangesCoverage).mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            mockGetCoverageData.mockResolvedValue(null);
            mockSaveCoverageData.mockResolvedValue();

            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockSaveCoverageData).toHaveBeenCalledWith(85.0, 'test-gist', 'test-token');
            expect(mockInfo).toHaveBeenCalledWith('Saved coverage data to gist for main branch: 85.0%');
        });
    });
});
