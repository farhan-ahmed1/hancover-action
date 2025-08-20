import { describe, it, expect } from 'vitest';
import { groupPackages } from '../src/group.js';
import { loadConfig, matchesPatterns } from '../src/config.js';
import { FileCov } from '../src/schema.js';

describe('Config System', () => {
    const testFiles: FileCov[] = [
        {
            path: 'src/parsers/lcov.ts',
            lines: { covered: 80, total: 100 },
            branches: { covered: 15, total: 20 },
            functions: { covered: 5, total: 5 },
            coveredLineNumbers: new Set([1, 2, 3])
        },
        {
            path: 'src/parsers/clover.ts',
            lines: { covered: 70, total: 80 },
            branches: { covered: 10, total: 15 },
            functions: { covered: 3, total: 4 },
            coveredLineNumbers: new Set([1, 2])
        },
        {
            path: 'src/comment.ts',
            lines: { covered: 120, total: 150 },
            branches: { covered: 25, total: 30 },
            functions: { covered: 8, total: 10 },
            coveredLineNumbers: new Set([1, 2, 3, 4])
        },
        {
            path: 'src/group.ts',
            lines: { covered: 90, total: 100 },
            branches: { covered: 20, total: 25 },
            functions: { covered: 6, total: 7 },
            coveredLineNumbers: new Set([1, 2])
        }
    ];

    it('should match patterns correctly', () => {
        expect(matchesPatterns('src/parsers/lcov.ts', ['src/parsers/**'])).toBe(true);
        expect(matchesPatterns('src/comment.ts', ['src/**'])).toBe(true);
        expect(matchesPatterns('src/parsers/lcov.ts', ['src/**'])).toBe(true);
        expect(matchesPatterns('test/example.ts', ['src/**'])).toBe(false);
    });

    it('should load and apply config correctly', () => {
        // This test will use the actual .coverage-report.json file in the repo
        const config = loadConfig();
        const result = groupPackages(testFiles, config);
        
        expect(result.pkgRows).toHaveLength(2);
        
        // Should have separate src/parsers group
        const parsersGroup = result.pkgRows.find(p => p.name === 'src/parsers');
        expect(parsersGroup).toBeDefined();
        expect(parsersGroup!.files).toHaveLength(2);
        
        // Should have src group (excluding parsers)
        const srcGroup = result.pkgRows.find(p => p.name === 'src');
        expect(srcGroup).toBeDefined();
        expect(srcGroup!.files).toHaveLength(2);
        
        // Verify file assignments
        expect(parsersGroup!.files.map(f => f.path)).toEqual(
            expect.arrayContaining(['src/parsers/lcov.ts', 'src/parsers/clover.ts'])
        );
        expect(srcGroup!.files.map(f => f.path)).toEqual(
            expect.arrayContaining(['src/comment.ts', 'src/group.ts'])
        );
    });

    it('should create top-level summary correctly', () => {
        const config = loadConfig();
        const result = groupPackages(testFiles, config);
        
        // Top-level should just be 'src' (first path segment)
        expect(result.topLevelRows).toHaveLength(1);
        expect(result.topLevelRows[0].name).toBe('src');
        expect(result.topLevelRows[0].files).toHaveLength(4);
    });
});
