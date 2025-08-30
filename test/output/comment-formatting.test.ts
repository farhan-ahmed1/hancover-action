import { describe, it, expect } from 'vitest';
import { renderComment } from '../../src/output/comment.js';
import { FileCov, ProjectCov, PkgCov } from '../../src/processing/schema.js';

describe('Comment Formatting', () => {
    it('should render clean expandable file tables', async () => {
        // Create test data similar to your src/parsers scenario
        const files: FileCov[] = [
            {
                path: 'src/comment.ts',
                lines: { covered: 100, total: 150 },
                branches: { covered: 20, total: 30 },
                functions: { covered: 8, total: 10 },
                coveredLineNumbers: new Set([1, 2, 3])
            },
            {
                path: 'src/parsers/lcov.ts',
                lines: { covered: 80, total: 100 },
                branches: { covered: 15, total: 20 },
                functions: { covered: 5, total: 5 },
                coveredLineNumbers: new Set([1, 2])
            },
            {
                path: 'src/parsers/clover.ts',
                lines: { covered: 70, total: 80 },
                branches: { covered: 10, total: 15 },
                functions: { covered: 3, total: 4 },
                coveredLineNumbers: new Set([1, 2])
            }
        ];

        const project: ProjectCov = {
            files,
            totals: {
                lines: { covered: 250, total: 330 },
                branches: { covered: 45, total: 65 },
                functions: { covered: 16, total: 19 }
            }
        };

        // Simulate the grouping result
        const prPackages: PkgCov[] = [
            {
                name: 'src',
                files: [files[0]],
                totals: {
                    lines: { covered: 100, total: 150 },
                    branches: { covered: 20, total: 30 },
                    functions: { covered: 8, total: 10 }
                }
            },
            {
                name: 'src/parsers',
                files: [files[1], files[2]],
                totals: {
                    lines: { covered: 150, total: 180 },
                    branches: { covered: 25, total: 35 },
                    functions: { covered: 8, total: 9 }
                }
            }
        ];

        const topLevelPackages: PkgCov[] = [
            {
                name: 'src',
                files,
                totals: project.totals
            }
        ];

        const comment = await renderComment({
            prProject: project,
            prPackages,
            topLevelPackages,
            minThreshold: 50
        });

        // Verify the comment structure
        expect(comment).toContain('## Coverage Report');
        expect(comment).toContain('### Top-level Packages (Summary)');
        expect(comment).toContain('Detailed Coverage by Package');
        expect(comment).toContain('<details>');
        expect(comment).toContain('<b>Files in <code>src/parsers</code></b>');
        
        // Verify the table formatting is clean
        expect(comment).not.toContain('| src/parsers | 83.0% (254/306) | 67.6% (50/74) | 100.0% (9/9) | ✅ |');
        expect(comment).not.toContain('Files in src\n| src/parsers |');
        
        // Verify expandable section is properly formatted
        const detailsMatch = comment.match(/<details>\s*<summary><b>Files in <code>src\/parsers<\/code><\/b><\/summary>([\s\S]*?)<\/details>/);
        expect(detailsMatch).toBeTruthy();
        if (detailsMatch) {
            const detailsContent = detailsMatch[1];
            expect(detailsContent).toContain('| File | Statements | Branches | Functions | Health |');
            expect(detailsContent).toContain('src/parsers/lcov.ts');
            expect(detailsContent).toContain('src/parsers/clover.ts');
        }
    });
});
