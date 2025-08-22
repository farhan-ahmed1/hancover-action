import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as core from '@actions/core';
import { parseLCOV } from '../src/parsers/lcov.js';
import { groupPackages } from '../src/group.js';
import { computeChangesCoverage, parseGitDiff } from '../src/changes.js';
import { runEnhancedCoverage } from '../src/enhanced.js';

// Mock all dependencies for runEnhancedCoverage tests
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

const mockSetOutput = vi.mocked(core.setOutput);
const mockSetFailed = vi.mocked(core.setFailed);
const mockInfo = vi.mocked(core.info);
const mockWarning = vi.mocked(core.warning);

// Import and mock at top level to ensure proper mocking
import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as configModule from '../src/config.js';
import * as inputsModule from '../src/inputs.js';
import * as parsersModule from '../src/parsers/index.js';
import * as commentModule from '../src/comment.js';
import * as coverageDataModule from '../src/coverage-data.js';
import * as changesModule from '../src/changes.js';

const mockExecSync = vi.mocked(childProcess.execSync);
const mockStatSync = vi.mocked(fs.statSync);
const mockLoadConfig = vi.mocked(configModule.loadConfig);
const mockReadInputs = vi.mocked(inputsModule.readInputs);
const mockParseAnyCoverage = vi.mocked(parsersModule.parseAnyCoverage);
const mockRenderComment = vi.mocked(commentModule.renderComment);
const mockUpsertStickyComment = vi.mocked(commentModule.upsertStickyComment);
const mockGetCoverageData = vi.mocked(coverageDataModule.getCoverageData);
const mockSaveCoverageData = vi.mocked(coverageDataModule.saveCoverageData);
const mockComputeDeltaCoverage = vi.mocked(changesModule.computeDeltaCoverage);

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

            expect(mockInfo).toHaveBeenCalledWith('🚀 Starting enhanced coverage analysis with performance optimizations...');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
            expect(mockSetOutput).toHaveBeenCalledWith('coverage-pct', '85.0');
            expect(mockSetOutput).toHaveBeenCalledWith('changes-coverage-pct', '100.0');
            expect(mockSetFailed).not.toHaveBeenCalled();
        });

        it('should fail with no coverage files provided', async () => {
            mockReadInputs.mockReturnValue({
                timeoutSeconds: 120,
                files: [],
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: '',
                gistToken: ''
            } as any);

            // Mock fs.statSync to return file stats
            vi.mocked(fs.statSync).mockReturnValue({ size: 1000 } as any);

            await expect(runEnhancedCoverage()).rejects.toThrow();
            
            // Check that the enhanced error format is used
            expect(mockSetFailed).toHaveBeenCalledWith(
                expect.stringContaining('Coverage processing failed: No coverage files provided')
            );
            expect(mockSetFailed).toHaveBeenCalledWith(
                expect.stringContaining('Context: {')
            );
            
            // Verify the context includes expected fields
            const setFailedCall = mockSetFailed.mock.calls[0][0];
            expect(setFailedCall).toContain('"files": []');
            expect(setFailedCall).toContain('"totalSize": 0');
            expect(setFailedCall).toContain('"timeElapsed":');
        });

        it('should include file sizes in enhanced error context', async () => {
            const testFiles = ['coverage/lcov.info', 'coverage/cobertura.xml'];
            mockReadInputs.mockReturnValue({
                timeoutSeconds: 120,
                files: testFiles,
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: '',
                gistToken: ''
            } as any);

            // Mock fs.statSync to return different file sizes
            vi.mocked(fs.statSync).mockImplementation((filePath) => {
                if (filePath === 'coverage/lcov.info') {
                    return { size: 5000 } as any;
                } else if (filePath === 'coverage/cobertura.xml') {
                    return { size: 3000 } as any;
                }
                return { size: 1000 } as any;
            });

            // Mock parseAnyCoverage to throw an error
            mockParseAnyCoverage.mockRejectedValue(new Error('Parsing failed'));

            await expect(runEnhancedCoverage()).rejects.toThrow();
            
            // Check that the enhanced error format includes file sizes
            expect(mockSetFailed).toHaveBeenCalledWith(
                expect.stringContaining('Coverage processing failed: Parsing failed')
            );
            expect(mockSetFailed).toHaveBeenCalledWith(
                expect.stringContaining('Context: {')
            );
            
            const setFailedCall = mockSetFailed.mock.calls[0][0];
            expect(setFailedCall).toContain('"totalSize": 8000'); // 5000 + 3000
            expect(setFailedCall).toContain(testFiles[0]);
            expect(setFailedCall).toContain(testFiles[1]);
        });

        it('should handle file stat errors gracefully in error context', async () => {
            const testFiles = ['nonexistent.info'];
            mockReadInputs.mockReturnValue({
                timeoutSeconds: 120,
                files: testFiles,
                baselineFiles: [],
                minThreshold: 50,
                warnOnly: false,
                commentMode: 'update' as const,
                gistId: '',
                gistToken: ''
            } as any);

            // Mock fs.statSync to throw (file doesn't exist)
            vi.mocked(fs.statSync).mockImplementation(() => {
                throw new Error('ENOENT: no such file or directory');
            });

            // Mock parseAnyCoverage to throw an error
            mockParseAnyCoverage.mockRejectedValue(new Error('File not found'));

            await expect(runEnhancedCoverage()).rejects.toThrow();
            
            // Should still include context even when file stat fails
            const setFailedCall = mockSetFailed.mock.calls[0][0];
            expect(setFailedCall).toContain('"totalSize": 0'); // Should be 0 when stat fails
            expect(setFailedCall).toContain('nonexistent.info');
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

        it('should save coverage data on master branch', async () => {
            // Test master branch detection
            process.env.GITHUB_REF = 'refs/heads/master';

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
                files: [{ path: 'src/example.ts', lines: { covered: 75, total: 100 }, branches: { covered: 30, total: 40 }, functions: { covered: 6, total: 8 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 75, total: 100 }, branches: { covered: 30, total: 40 }, functions: { covered: 6, total: 8 } }
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

            expect(mockSaveCoverageData).toHaveBeenCalledWith(75.0, 'test-gist', 'test-token');
            expect(mockInfo).toHaveBeenCalledWith('Saved coverage data to gist for main branch: 75.0%');
        });

        it('should handle errors when saving coverage data fails', async () => {
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
            // Mock save to fail
            mockSaveCoverageData.mockRejectedValue(new Error('Failed to save to gist'));

            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockWarning).toHaveBeenCalledWith('Failed to save coverage data: Error: Failed to save to gist');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });

        it('should fetch baseline coverage from gist and set coverage delta output', async () => {
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

            // Mock gist coverage data available
            mockGetCoverageData.mockResolvedValue(80.0);

            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockInfo).toHaveBeenCalledWith('✅ Successfully fetched baseline coverage from gist: 80.0%');
            expect(mockSetOutput).toHaveBeenCalledWith('coverage-delta', '5.0'); // 85.0 - 80.0
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });

        it('should process baseline files when gist data is not available', async () => {
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: ['baseline-coverage/lcov.info'],
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

            const mockMainProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 75, total: 100 }, branches: { covered: 35, total: 50 }, functions: { covered: 7, total: 10 }, coveredLineNumbers: new Set([1, 2]), package: 'src' }],
                totals: { lines: { covered: 75, total: 100 }, branches: { covered: 35, total: 50 }, functions: { covered: 7, total: 10 } }
            };

            mockParseAnyCoverage.mockResolvedValueOnce(mockProject).mockResolvedValueOnce(mockMainProject);

            vi.mocked(groupPackages).mockReturnValue({ pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }], topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }] });

            mockLoadConfig.mockReturnValue({ groups: [], fallback: { smartDepth: 'auto', promoteThreshold: 0.8 }, ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 } });

            mockExecSync.mockReturnValue('');

            vi.mocked(parseGitDiff).mockReturnValue({});
            vi.mocked(computeChangesCoverage).mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            // Mock import changes to use computeDeltaCoverage
            mockComputeDeltaCoverage.mockReturnValue({
                packages: []
            });

            mockGetCoverageData.mockResolvedValue(null);

            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockInfo).toHaveBeenCalledWith('❌ No baseline coverage available from gist');
            expect(mockInfo).toHaveBeenCalledWith('Parsing baseline coverage from files...');
            expect(mockInfo).toHaveBeenCalledWith('Main branch coverage from files: 75.0%');
            expect(mockSetOutput).toHaveBeenCalledWith('coverage-delta', '10.0'); // 85.0 - 75.0
        });

        it('should handle baseline file processing errors', async () => {
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: ['baseline-coverage/lcov.info'],
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

            mockParseAnyCoverage.mockResolvedValueOnce(mockProject).mockRejectedValueOnce(new Error('Failed to parse baseline'));

            vi.mocked(groupPackages).mockReturnValue({ pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }], topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }] });

            mockLoadConfig.mockReturnValue({ groups: [], fallback: { smartDepth: 'auto', promoteThreshold: 0.8 }, ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 } });

            mockExecSync.mockReturnValue('');

            vi.mocked(parseGitDiff).mockReturnValue({});
            vi.mocked(computeChangesCoverage).mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            mockGetCoverageData.mockResolvedValue(null);

            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockWarning).toHaveBeenCalledWith('Failed to process baseline coverage: Error: Failed to parse baseline');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });

        it('should handle threshold failures with warnOnly mode', async () => {
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: [],
                minThreshold: 90, // High threshold to trigger failure
                warnOnly: true, // Enable warn-only mode
                commentMode: 'update' as const,
                gistId: '',
                gistToken: ''
            } as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 40, total: 100 }, branches: { covered: 20, total: 50 }, functions: { covered: 4, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 40, total: 100 }, branches: { covered: 20, total: 50 }, functions: { covered: 4, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            vi.mocked(groupPackages).mockReturnValue({ pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }], topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }] });

            mockLoadConfig.mockReturnValue({ groups: [], fallback: { smartDepth: 'auto', promoteThreshold: 0.8 }, ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 } });

            mockExecSync.mockReturnValue('');

            vi.mocked(parseGitDiff).mockReturnValue({});
            vi.mocked(computeChangesCoverage).mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 2, total: 10 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            mockGetCoverageData.mockResolvedValue(null);

            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockWarning).toHaveBeenCalledWith('Project coverage 40.0% is below threshold 90%');
            expect(mockWarning).toHaveBeenCalledWith('Changes coverage 20.0% is below threshold 90%');
            expect(mockSetFailed).not.toHaveBeenCalled();
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });

        it('should handle threshold failures without warnOnly mode', async () => {
            mockReadInputs.mockReturnValue({
                files: ['coverage/lcov.info'],
                baselineFiles: [],
                minThreshold: 90, // High threshold to trigger failure
                warnOnly: false, // Disable warn-only mode
                commentMode: 'update' as const,
                gistId: '',
                gistToken: ''
            } as any);

            const mockProject = {
                files: [{ path: 'src/example.ts', lines: { covered: 40, total: 100 }, branches: { covered: 20, total: 50 }, functions: { covered: 4, total: 10 }, coveredLineNumbers: new Set([1, 2, 3]), package: 'src' }],
                totals: { lines: { covered: 40, total: 100 }, branches: { covered: 20, total: 50 }, functions: { covered: 4, total: 10 } }
            };
            mockParseAnyCoverage.mockResolvedValue(mockProject);

            vi.mocked(groupPackages).mockReturnValue({ pkgRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }], topLevelRows: [{ name: 'src', files: mockProject.files, totals: mockProject.totals }] });

            mockLoadConfig.mockReturnValue({ groups: [], fallback: { smartDepth: 'auto', promoteThreshold: 0.8 }, ui: { expandFilesFor: [], maxDeltaRows: 10, minPassThreshold: 50 } });

            mockExecSync.mockReturnValue('');

            vi.mocked(parseGitDiff).mockReturnValue({});
            vi.mocked(computeChangesCoverage).mockReturnValue({
                files: [], packages: [], totals: { lines: { covered: 2, total: 10 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            });

            mockGetCoverageData.mockResolvedValue(null);

            mockRenderComment.mockResolvedValue('Mock comment');
            mockUpsertStickyComment.mockResolvedValue();

            await runEnhancedCoverage();

            expect(mockSetFailed).toHaveBeenCalledWith('Project coverage 40.0% is below threshold 90%');
            expect(mockSetFailed).toHaveBeenCalledWith('Changes coverage 20.0% is below threshold 90%');
            expect(mockInfo).toHaveBeenCalledWith('Enhanced coverage analysis completed successfully');
        });
    });
});
