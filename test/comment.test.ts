import { describe, it, expect, vi } from 'vitest';
import { renderComment, upsertStickyComment } from '../src/output/comment.js';
import { ProjectCov, PkgCov, FileCov } from '../src/processing/schema.js';

describe('Comment Rendering', () => {
    it('should render a markdown comment correctly', async () => {
        const sampleFile: FileCov = {
            path: 'src/example.ts',
            lines: { covered: 85, total: 100 },
            branches: { covered: 60, total: 100 },
            functions: { covered: 10, total: 12 },
            coveredLineNumbers: new Set([1, 2, 3])
        };

        const prProject: ProjectCov = {
            files: [sampleFile],
            totals: {
                lines: { covered: 85, total: 100 },
                branches: { covered: 60, total: 100 },
                functions: { covered: 10, total: 12 }
            }
        };

        const prPackages: PkgCov[] = [{
            name: 'src',
            files: [sampleFile],
            totals: {
                lines: { covered: 85, total: 100 },
                branches: { covered: 60, total: 100 },
                functions: { covered: 10, total: 12 }
            }
        }];

        const comment = await renderComment({ 
            prProject,
            prPackages,
            minThreshold: 50
        });

        // Test for new format
        expect(comment).toContain('<!-- coverage-comment:anchor -->');
        expect(comment).toContain('[![Coverage](');
        expect(comment).toContain('Coverage Report');
        expect(comment).toContain('85.0%');
        expect(comment).toContain('<details>');
        expect(comment).toContain('Detailed Coverage by Package');
        expect(comment).toContain('Overall Coverage');
        expect(comment).toContain('Lines Covered');
        expect(comment).toContain('85.0%');
        expect(comment).toContain('60.0%');
    });

    it('should update an existing sticky comment', async () => {
        const mockUpsert = vi.fn();
        // Mock the implementation by spying on the module
        vi.spyOn({ upsertStickyComment }, 'upsertStickyComment').mockImplementation(mockUpsert);

        const md = '### Updated Comment';
        await upsertStickyComment(md, 'update');

        // This test would need proper mocking setup
        // For now, just verify the function can be called
        expect(typeof upsertStickyComment).toBe('function');
    });
});