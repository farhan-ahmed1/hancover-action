import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as core from '@actions/core';
import * as github from '@actions/github';
import { renderComment, upsertStickyComment } from '../../src/output/comment.js';
import { ProjectCov, PkgCov, FileCov } from '../../src/processing/schema.js';
import { DeltaCoverage } from '../../src/processing/changes.js';

// Mock dependencies
vi.mock('@actions/core');
vi.mock('@actions/github');
vi.mock('../../src/infrastructure/config.js', () => ({
    loadConfig: vi.fn(() => ({}))
}));

const mockGetInput = vi.mocked(core.getInput);
const mockGetInfo = vi.mocked(core.info);
const mockGetWarning = vi.mocked(core.warning);
const mockGetError = vi.mocked(core.error);
const mockGetOctokit = vi.mocked(github.getOctokit);

describe('comment - comprehensive coverage', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        
        // Set up default github context mock
        Object.defineProperty(github, 'context', {
            value: {
                payload: {
                    pull_request: {
                        number: 123
                    }
                },
                repo: {
                    owner: 'test-owner',
                    repo: 'test-repo'
                }
            },
            writable: true
        });

        // Clear environment variables
        delete process.env.GITHUB_TOKEN;
    });

    afterEach(() => {
        vi.resetAllMocks();
    });

    const createSampleFile = (path: string, lines: any, branches: any, functions: any, pkg?: string): FileCov => ({
        path,
        lines,
        branches, 
        functions,
        coveredLineNumbers: new Set([1, 2, 3]),
        package: pkg
    });

    const createSampleProject = (files: FileCov[]): ProjectCov => {
        const totals = files.reduce((acc, file) => ({
            lines: { 
                covered: acc.lines.covered + file.lines.covered, 
                total: acc.lines.total + file.lines.total 
            },
            branches: { 
                covered: acc.branches.covered + file.branches.covered, 
                total: acc.branches.total + file.branches.total 
            },
            functions: { 
                covered: acc.functions.covered + file.functions.covered, 
                total: acc.functions.total + file.functions.total 
            }
        }), { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } });

        return { files, totals };
    };

    describe('renderComment', () => {
        it('should render comment without main branch coverage', async () => {
            const file = createSampleFile('src/example.ts', { covered: 85, total: 100 }, { covered: 60, total: 100 }, { covered: 10, total: 12 }, 'src');
            const prProject = createSampleProject([file]);
            const prPackages: PkgCov[] = [{
                name: 'src',
                files: [file],
                totals: prProject.totals
            }];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                minThreshold: 50
            });

            expect(comment).toContain('<!-- coverage-comment:anchor -->');
            expect(comment).toContain('Coverage Report');
            expect(comment).toContain('85.0%');
            expect(comment).toContain('**Overall Coverage:** 85.0%');
            expect(comment).toContain('**Lines Covered:** 85/100');
            expect(comment).not.toContain('Changes made in this PR');
            expect(comment).toContain('Minimum pass threshold is 50.0%');
        });

        it('should render comment with main branch coverage (positive delta)', async () => {
            const file = createSampleFile('src/example.ts', { covered: 85, total: 100 }, { covered: 60, total: 100 }, { covered: 10, total: 12 }, 'src');
            const prProject = createSampleProject([file]);
            const prPackages: PkgCov[] = [{
                name: 'src',
                files: [file],
                totals: prProject.totals
            }];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                mainBranchCoverage: 80.0,
                minThreshold: 50
            });

            expect(comment).toContain('Changes made in this PR increased coverage by 5.0 percentage points');
            expect(comment).toContain('[![Changes](https://img.shields.io/badge/changes-%2B5.0%25-brightgreen)](#)');
        });

        it('should render comment with main branch coverage (negative delta)', async () => {
            const file = createSampleFile('src/example.ts', { covered: 75, total: 100 }, { covered: 60, total: 100 }, { covered: 10, total: 12 }, 'src');
            const prProject = createSampleProject([file]);
            const prPackages: PkgCov[] = [{
                name: 'src',
                files: [file],
                totals: prProject.totals
            }];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                mainBranchCoverage: 80.0,
                minThreshold: 50
            });

            expect(comment).toContain('Changes made in this PR decreased coverage by 5.0 percentage points');
            expect(comment).toContain('[![Changes](https://img.shields.io/badge/changes-%E2%88%925.0%25-red)](#)');
        });

        it('should render comment with main branch coverage (zero delta)', async () => {
            const file = createSampleFile('src/example.ts', { covered: 80, total: 100 }, { covered: 60, total: 100 }, { covered: 10, total: 12 }, 'src');
            const prProject = createSampleProject([file]);
            const prPackages: PkgCov[] = [{
                name: 'src',
                files: [file],
                totals: prProject.totals
            }];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                mainBranchCoverage: 80.0,
                minThreshold: 50
            });

            expect(comment).toContain('Changes made in this PR did not affect overall coverage');
        });

        it('should render comment with top-level packages', async () => {
            const file1 = createSampleFile('src/example.ts', { covered: 85, total: 100 }, { covered: 60, total: 100 }, { covered: 10, total: 12 }, 'src');
            const file2 = createSampleFile('test/example.test.ts', { covered: 45, total: 50 }, { covered: 20, total: 25 }, { covered: 5, total: 8 }, 'test');
            
            const prProject = createSampleProject([file1, file2]);
            const prPackages: PkgCov[] = [
                { name: 'src', files: [file1], totals: { lines: { covered: 85, total: 100 }, branches: { covered: 60, total: 100 }, functions: { covered: 10, total: 12 } } },
                { name: 'test', files: [file2], totals: { lines: { covered: 45, total: 50 }, branches: { covered: 20, total: 25 }, functions: { covered: 5, total: 8 } } }
            ];
            const topLevelPackages: PkgCov[] = [
                { name: 'src', files: [file1], totals: { lines: { covered: 85, total: 100 }, branches: { covered: 60, total: 100 }, functions: { covered: 10, total: 12 } } }
            ];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                topLevelPackages,
                minThreshold: 50
            });

            expect(comment).toContain('Top-level Packages (Summary)');
            expect(comment).toContain('85.0% (85/100)');
        });

        it('should render comment with top-level packages having multiple packages (with summary)', async () => {
            const file1 = createSampleFile('src/example.ts', { covered: 85, total: 100 }, { covered: 60, total: 100 }, { covered: 10, total: 12 }, 'src');
            const file2 = createSampleFile('test/example.test.ts', { covered: 45, total: 50 }, { covered: 20, total: 25 }, { covered: 5, total: 8 }, 'test');
            
            const prProject = createSampleProject([file1, file2]);
            const prPackages: PkgCov[] = [
                { name: 'src', files: [file1], totals: { lines: { covered: 85, total: 100 }, branches: { covered: 60, total: 100 }, functions: { covered: 10, total: 12 } } },
                { name: 'test', files: [file2], totals: { lines: { covered: 45, total: 50 }, branches: { covered: 20, total: 25 }, functions: { covered: 5, total: 8 } } }
            ];
            const topLevelPackages: PkgCov[] = [
                { name: 'src', files: [file1], totals: { lines: { covered: 85, total: 100 }, branches: { covered: 60, total: 100 }, functions: { covered: 10, total: 12 } } },
                { name: 'test', files: [file2], totals: { lines: { covered: 45, total: 50 }, branches: { covered: 20, total: 25 }, functions: { covered: 5, total: 8 } } }
            ];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                topLevelPackages,
                minThreshold: 50
            });

            expect(comment).toContain('Top-level Packages (Summary)');
            expect(comment).toContain('**Summary**'); // Should include summary row
            expect(comment).toContain('86.7%'); // Combined percentage (130/150)
        });

        it('should render comment with delta coverage', async () => {
            const file = createSampleFile('src/example.ts', { covered: 85, total: 100 }, { covered: 60, total: 100 }, { covered: 10, total: 12 }, 'src');
            const prProject = createSampleProject([file]);
            const prPackages: PkgCov[] = [{
                name: 'src',
                files: [file],
                totals: prProject.totals
            }];

            const deltaCoverage: DeltaCoverage = {
                packages: [
                    {
                        name: 'src',
                        linesDeltas: { pr: 85, main: 80, delta: 5 },
                        branchesDeltas: { pr: 60, main: 55, delta: 5 },
                        functionsDeltas: { pr: 83.3, main: 75, delta: 8.3 }
                    }
                ]
            };

            const comment = await renderComment({ 
                prProject,
                prPackages,
                deltaCoverage,
                minThreshold: 50
            });

            expect(comment).toContain('Coverage Delta (PR vs main)');
            expect(comment).toContain('+5.0%');
            expect(comment).toContain('**Summary**');
        });

        it('should render comment with expandable file tables', async () => {
            const file1 = createSampleFile('src/file1.ts', { covered: 40, total: 50 }, { covered: 30, total: 50 }, { covered: 5, total: 6 }, 'src');
            const file2 = createSampleFile('src/file2.ts', { covered: 45, total: 50 }, { covered: 30, total: 50 }, { covered: 5, total: 6 }, 'src');
            
            const prProject = createSampleProject([file1, file2]);
            const prPackages: PkgCov[] = [{
                name: 'src',
                files: [file1, file2],
                totals: { lines: { covered: 85, total: 100 }, branches: { covered: 60, total: 100 }, functions: { covered: 10, total: 12 } }
            }];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                minThreshold: 50
            });

            expect(comment).toContain('<details>');
            expect(comment).toContain('Files in <code>src</code>');
            expect(comment).toContain('src/file1.ts');
            expect(comment).toContain('src/file2.ts');
            expect(comment).toContain('**Total**'); // Package total row
        });

        it('should handle packages with no coverage data', async () => {
            const prProject: ProjectCov = {
                files: [],
                totals: { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
            };
            const prPackages: PkgCov[] = [];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                minThreshold: 50
            });

            expect(comment).toContain('_No coverage data available_');
        });

        it('should render delta table with more than 10 packages (showing collapsed section)', async () => {
            // Create 15 packages to test the collapse feature
            const packages = Array.from({ length: 15 }, (_, i) => ({
                name: `package-${i}`,
                linesDeltas: { pr: 80 + i, main: 75 + i, delta: 5 },
                branchesDeltas: { pr: 70 + i, main: 65 + i, delta: 5 },
                functionsDeltas: { pr: 90 + i, main: 85 + i, delta: 5 }
            }));

            const deltaCoverage: DeltaCoverage = { packages };

            const file = createSampleFile('src/example.ts', { covered: 85, total: 100 }, { covered: 60, total: 100 }, { covered: 10, total: 12 }, 'src');
            const prProject = createSampleProject([file]);
            const prPackages: PkgCov[] = [{
                name: 'src',
                files: [file],
                totals: prProject.totals
            }];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                deltaCoverage,
                minThreshold: 50
            });

            expect(comment).toContain('Coverage Delta (PR vs main)');
            expect(comment).toContain('Show 5 more packages...'); // 15 - 10 = 5
            expect(comment).toContain('</details>');
        });

        it('should handle empty delta coverage', async () => {
            const file = createSampleFile('src/example.ts', { covered: 85, total: 100 }, { covered: 60, total: 100 }, { covered: 10, total: 12 }, 'src');
            const prProject = createSampleProject([file]);
            const prPackages: PkgCov[] = [{
                name: 'src',
                files: [file],
                totals: prProject.totals
            }];

            const deltaCoverage: DeltaCoverage = { packages: [] };

            const comment = await renderComment({ 
                prProject,
                prPackages,
                deltaCoverage,
                minThreshold: 50
            });

            expect(comment).not.toContain('Coverage Delta (PR vs main)');
        });

        it('should handle custom config for expandable files', async () => {
            // Mock config to return expandFilesFor configuration
            const { loadConfig } = await import('../../src/infrastructure/config.js');
            vi.mocked(loadConfig).mockReturnValue({
                groups: [],
                fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
                ui: {
                    expandFilesFor: ['src'],
                    maxDeltaRows: 10,
                    minPassThreshold: 50
                }
            });

            const file1 = createSampleFile('src/file1.ts', { covered: 40, total: 50 }, { covered: 30, total: 50 }, { covered: 5, total: 6 }, 'src');
            const file2 = createSampleFile('test/file2.ts', { covered: 45, total: 50 }, { covered: 30, total: 50 }, { covered: 5, total: 6 }, 'test');
            
            const prProject = createSampleProject([file1, file2]);
            const prPackages: PkgCov[] = [
                { name: 'src', files: [file1], totals: { lines: { covered: 40, total: 50 }, branches: { covered: 30, total: 50 }, functions: { covered: 5, total: 6 } } },
                { name: 'test', files: [file2], totals: { lines: { covered: 45, total: 50 }, branches: { covered: 30, total: 50 }, functions: { covered: 5, total: 6 } } }
            ];

            const comment = await renderComment({ 
                prProject,
                prPackages,
                minThreshold: 50
            });

            // Should have both src and test packages with their files
            expect(comment).toContain('src | 80.0% (40/50)');
            expect(comment).toContain('test | 90.0% (45/50)');
        });
    });

    describe('upsertStickyComment', () => {
        it('should skip comment when no GitHub token provided', async () => {
            mockGetInput.mockReturnValue('');
            delete process.env.GITHUB_TOKEN;

            await upsertStickyComment('test comment');

            expect(mockGetWarning).toHaveBeenCalledWith('No GitHub token provided, skipping comment update');
        });

        it('should skip comment when not a pull request', async () => {
            mockGetInput.mockReturnValue('test-token');
            
            // Mock context without pull_request
            Object.defineProperty(github, 'context', {
                value: {
                    payload: {},
                    repo: { owner: 'test-owner', repo: 'test-repo' }
                },
                writable: true
            });

            await upsertStickyComment('test comment');

            expect(mockGetInfo).toHaveBeenCalledWith('Not a pull request, skipping comment');
        });

        it('should create new comment when no existing comment found', async () => {
            mockGetInput.mockReturnValue('test-token');
            
            const mockOctokit = {
                rest: {
                    issues: {
                        listComments: vi.fn().mockResolvedValue({ data: [] }),
                        createComment: vi.fn().mockResolvedValue({ data: { id: 456 } })
                    }
                }
            };

            mockGetOctokit.mockReturnValue(mockOctokit as any);

            await upsertStickyComment('test comment');

            expect(mockOctokit.rest.issues.listComments).toHaveBeenCalledWith({
                owner: 'test-owner',
                repo: 'test-repo',
                issue_number: 123,
                per_page: 100
            });

            expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
                owner: 'test-owner',
                repo: 'test-repo',
                issue_number: 123,
                body: 'test comment'
            });

            expect(mockGetInfo).toHaveBeenCalledWith('Created new coverage comment');
        });

        it('should update existing comment when found', async () => {
            mockGetInput.mockReturnValue('test-token');
            
            const existingComment = {
                id: 789,
                body: '<!-- coverage-comment:anchor -->\nOld content'
            };

            const mockOctokit = {
                rest: {
                    issues: {
                        listComments: vi.fn().mockResolvedValue({ data: [existingComment] }),
                        updateComment: vi.fn().mockResolvedValue({ data: { id: 789 } })
                    }
                }
            };

            mockGetOctokit.mockReturnValue(mockOctokit as any);

            await upsertStickyComment('test comment');

            expect(mockOctokit.rest.issues.updateComment).toHaveBeenCalledWith({
                owner: 'test-owner',
                repo: 'test-repo',
                comment_id: 789,
                body: 'test comment'
            });

            expect(mockGetInfo).toHaveBeenCalledWith('Updated existing coverage comment (ID: 789)');
        });

        it('should handle multiple existing comments and use the latest', async () => {
            mockGetInput.mockReturnValue('test-token');
            
            const comments = [
                { id: 111, body: '## Coverage Report\nOld content 1' },
                { id: 222, body: '<!-- coverage-comment:anchor -->\nOld content 2' },
                { id: 333, body: '## Coverage Report\nOld content 3' }
            ];

            const mockOctokit = {
                rest: {
                    issues: {
                        listComments: vi.fn().mockResolvedValue({ data: comments }),
                        updateComment: vi.fn().mockResolvedValue({ data: { id: 333 } })
                    }
                }
            };

            mockGetOctokit.mockReturnValue(mockOctokit as any);

            await upsertStickyComment('test comment');

            expect(mockGetWarning).toHaveBeenCalledWith('Found multiple coverage comments (3), using the latest one');
            expect(mockOctokit.rest.issues.updateComment).toHaveBeenCalledWith({
                owner: 'test-owner',
                repo: 'test-repo',
                comment_id: 333, // Latest comment
                body: 'test comment'
            });
        });

        it('should create new comment when mode is "new"', async () => {
            mockGetInput.mockReturnValue('test-token');
            
            const mockOctokit = {
                rest: {
                    issues: {
                        createComment: vi.fn().mockResolvedValue({ data: { id: 456 } })
                    }
                }
            };

            mockGetOctokit.mockReturnValue(mockOctokit as any);

            await upsertStickyComment('test comment', 'new');

            expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
                owner: 'test-owner',
                repo: 'test-repo',
                issue_number: 123,
                body: 'test comment'
            });

            expect(mockGetInfo).toHaveBeenCalledWith('Created new coverage comment');
        });

        it('should handle API errors gracefully', async () => {
            mockGetInput.mockReturnValue('test-token');
            
            const mockOctokit = {
                rest: {
                    issues: {
                        listComments: vi.fn().mockRejectedValue(new Error('API Error'))
                    }
                }
            };

            mockGetOctokit.mockReturnValue(mockOctokit as any);

            await expect(upsertStickyComment('test comment')).rejects.toThrow('API Error');
            expect(mockGetError).toHaveBeenCalledWith('Failed to upsert comment: Error: API Error');
        });

        it('should use GITHUB_TOKEN environment variable as fallback', async () => {
            mockGetInput.mockReturnValue('');
            process.env.GITHUB_TOKEN = 'env-token';
            
            const mockOctokit = {
                rest: {
                    issues: {
                        listComments: vi.fn().mockResolvedValue({ data: [] }),
                        createComment: vi.fn().mockResolvedValue({ data: { id: 456 } })
                    }
                }
            };

            mockGetOctokit.mockReturnValue(mockOctokit as any);

            await upsertStickyComment('test comment');

            expect(mockGetOctokit).toHaveBeenCalledWith('env-token');
        });

        it('should handle comments with null body gracefully', async () => {
            mockGetInput.mockReturnValue('test-token');
            
            const comments = [
                { id: 111, body: null },
                { id: 222, body: '<!-- coverage-comment:anchor -->\nValid content' }
            ];

            const mockOctokit = {
                rest: {
                    issues: {
                        listComments: vi.fn().mockResolvedValue({ data: comments }),
                        updateComment: vi.fn().mockResolvedValue({ data: { id: 222 } })
                    }
                }
            };

            mockGetOctokit.mockReturnValue(mockOctokit as any);

            await upsertStickyComment('test comment');

            expect(mockOctokit.rest.issues.updateComment).toHaveBeenCalledWith({
                owner: 'test-owner',
                repo: 'test-repo',
                comment_id: 222,
                body: 'test comment'
            });
        });
    });
});
