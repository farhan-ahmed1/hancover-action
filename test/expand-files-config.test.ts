import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderComment } from '../src/comment.js';
import type { CommentData } from '../src/comment.js';
import type { PkgCov, ProjectCov, FileCov } from '../src/schema.js';

// Mock the config loading to avoid interfering with the real config file
vi.mock('../src/config.js', () => ({
    loadConfig: vi.fn()
}));

describe('expandFilesFor Configuration', () => {
    const mockLoadConfig = vi.fn();

    beforeEach(async () => {
        vi.clearAllMocks();
        
        // Import and setup the mock after clearing
        const configModule = await import('../src/config.js');
        vi.mocked(configModule.loadConfig).mockImplementation(mockLoadConfig);
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

    const createMockData = (): CommentData => {
        // Create parser files
        const cloverFile = createSampleFile('src/parsers/clover.ts', 
            { covered: 85, total: 100 }, 
            { covered: 75, total: 85 }, 
            { covered: 9, total: 10 }, 
            'src/parsers'
        );
        const lcovFile = createSampleFile('src/parsers/lcov.ts', 
            { covered: 90, total: 100 }, 
            { covered: 80, total: 90 }, 
            { covered: 10, total: 10 }, 
            'src/parsers'
        );

        // Create src files
        const badgesFile = createSampleFile('src/badges.ts', 
            { covered: 95, total: 100 }, 
            { covered: 85, total: 90 }, 
            { covered: 8, total: 10 }, 
            'src'
        );
        const changesFile = createSampleFile('src/changes.ts', 
            { covered: 88, total: 100 }, 
            { covered: 77, total: 85 }, 
            { covered: 9, total: 10 }, 
            'src'
        );
        const commentFile = createSampleFile('src/comment.ts', 
            { covered: 92, total: 100 }, 
            { covered: 82, total: 90 }, 
            { covered: 10, total: 10 }, 
            'src'
        );

        const parserFiles = [cloverFile, lcovFile];
        const srcFiles = [badgesFile, changesFile, commentFile];
        const allFiles = [...parserFiles, ...srcFiles];

        // Calculate totals for packages
        const parsersTotal = parserFiles.reduce((acc, file) => ({
            lines: { covered: acc.lines.covered + file.lines.covered, total: acc.lines.total + file.lines.total },
            branches: { covered: acc.branches.covered + file.branches.covered, total: acc.branches.total + file.branches.total },
            functions: { covered: acc.functions.covered + file.functions.covered, total: acc.functions.total + file.functions.total }
        }), { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } });

        const srcTotal = srcFiles.reduce((acc, file) => ({
            lines: { covered: acc.lines.covered + file.lines.covered, total: acc.lines.total + file.lines.total },
            branches: { covered: acc.branches.covered + file.branches.covered, total: acc.branches.total + file.branches.total },
            functions: { covered: acc.functions.covered + file.functions.covered, total: acc.functions.total + file.functions.total }
        }), { lines: { covered: 0, total: 0 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } });

        const mockPackages: PkgCov[] = [
            {
                name: 'src/parsers',
                files: parserFiles,
                totals: parsersTotal
            },
            {
                name: 'src',
                files: srcFiles,
                totals: srcTotal
            }
        ];

        const mockProject = createSampleProject(allFiles);

        return {
            prProject: mockProject,
            prPackages: mockPackages,
            topLevelPackages: mockPackages // Use same packages for top-level
        };
    };

    it('should only expand packages listed in expandFilesFor', async () => {
        // Mock config with specific expandFilesFor
        mockLoadConfig.mockReturnValue({
            groups: [],
            fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
            ui: {
                expandFilesFor: ['src/parsers'], // Only src/parsers should be expandable
                maxDeltaRows: 10,
                minPassThreshold: 50
            }
        });

        const mockData = createMockData();
        const comment = await renderComment(mockData);

        // Check that src/parsers files are included (expandable)
        expect(comment).toContain('src/parsers/clover.ts');
        expect(comment).toContain('src/parsers/lcov.ts');

        // Check that src files are NOT included (not expandable)
        expect(comment).not.toContain('src/badges.ts');
        expect(comment).not.toContain('src/changes.ts');
        expect(comment).not.toContain('src/comment.ts');

        // Count <details> sections - should be 2:
        // 1. "Detailed Coverage by Package" (main table)
        // 2. "Files in src/parsers" (the one expandable package)
        const detailsMatches = comment.match(/<details>/g);
        expect(detailsMatches).toHaveLength(2);

        // Verify specific expandable sections
        expect(comment).toContain('Files in <code>src/parsers</code>');
        expect(comment).not.toContain('Files in <code>src</code>');
    });

    it('should expand all packages when expandFilesFor is empty (fallback behavior)', async () => {
        // Mock config with no expandFilesFor (undefined) - should use fallback behavior
        mockLoadConfig.mockReturnValue({
            groups: [],
            fallback: { smartDepth: 'auto', promoteThreshold: 0.8 },
            ui: {
                maxDeltaRows: 10,
                minPassThreshold: 50
                // No expandFilesFor property - should use fallback behavior
            }
        });

        const mockData = createMockData();
        const comment = await renderComment(mockData);

        // With fallback behavior, both packages should be expandable (file count >= 2)
        expect(comment).toContain('src/parsers/clover.ts');
        expect(comment).toContain('src/badges.ts');

        // Should have 3 <details> sections:
        // 1. "Detailed Coverage by Package"
        // 2. "Files in src/parsers"
        // 3. "Files in src"
        const detailsMatches = comment.match(/<details>/g);
        expect(detailsMatches).toHaveLength(3);
    });
});
