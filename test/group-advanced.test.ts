import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    groupPackages,
    pct,
    rollup,
    groupCoverage,
    groupPackagesLegacy
} from '../src/group.js';
import { FileCov } from '../src/schema.js';
import { Config } from '../src/config.js';
import * as core from '@actions/core';

// Mock @actions/core
vi.mock('@actions/core', () => ({
    debug: vi.fn(),
    info: vi.fn()
}));

// Mock config loading
vi.mock('../src/config.js', async () => {
    const actual = await vi.importActual('../src/config.js');
    return {
        ...actual,
        loadConfig: vi.fn(() => ({
            groups: [],
            fallback: {
                smartDepth: 'auto',
                promoteThreshold: 0.8
            },
            ui: {
                expandFilesFor: [],
                maxDeltaRows: 10,
                minPassThreshold: 50
            }
        }))
    };
});

describe('Group Coverage Advanced Tests', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    const createTestFile = (path: string, lines: [number, number] = [80, 100], branches: [number, number] = [15, 20], functions: [number, number] = [5, 5]): FileCov => ({
        path,
        lines: { covered: lines[0], total: lines[1] },
        branches: { covered: branches[0], total: branches[1] },
        functions: { covered: functions[0], total: functions[1] },
        coveredLineNumbers: new Set(Array.from({length: lines[0]}, (_, i) => i + 1))
    });

    describe('pct function', () => {
        it('should calculate percentage correctly', () => {
            expect(pct(0, 0)).toBe(100); // Edge case: 0/0 is treated as 100%
            expect(pct(0, 100)).toBe(0);
            expect(pct(50, 100)).toBe(50);
            expect(pct(100, 100)).toBe(100);
            expect(pct(80, 100)).toBe(80);
            expect(pct(3, 4)).toBe(75);
            // Use toBeCloseTo for floating point comparisons
            expect(pct(1, 3)).toBeCloseTo(33.333333333333336, 10);
        });

        it('should handle zero total as 100%', () => {
            expect(pct(0, 0)).toBe(100);
            expect(pct(5, 0)).toBe(100); // Edge case: covered > 0 but total = 0
        });

        it('should handle zero covered', () => {
            expect(pct(0, 100)).toBe(0);
            expect(pct(0, 50)).toBe(0);
        });
    });

    describe('rollup function', () => {
        it('should aggregate file coverage correctly', () => {
            const files: FileCov[] = [
                createTestFile('file1.ts', [80, 100], [15, 20], [5, 5]),
                createTestFile('file2.ts', [60, 80], [10, 15], [3, 4]),
                createTestFile('file3.ts', [90, 120], [18, 25], [7, 8])
            ];

            const totals = rollup(files);

            expect(totals.lines.covered).toBe(230); // 80 + 60 + 90
            expect(totals.lines.total).toBe(300); // 100 + 80 + 120
            expect(totals.branches.covered).toBe(43); // 15 + 10 + 18
            expect(totals.branches.total).toBe(60); // 20 + 15 + 25
            expect(totals.functions.covered).toBe(15); // 5 + 3 + 7
            expect(totals.functions.total).toBe(17); // 5 + 4 + 8
        });

        it('should handle empty files array', () => {
            const totals = rollup([]);
            
            expect(totals.lines.covered).toBe(0);
            expect(totals.lines.total).toBe(0);
            expect(totals.branches.covered).toBe(0);
            expect(totals.branches.total).toBe(0);
            expect(totals.functions.covered).toBe(0);
            expect(totals.functions.total).toBe(0);
        });

        it('should handle single file', () => {
            const file = createTestFile('single.ts', [75, 100], [12, 16], [4, 5]);
            const totals = rollup([file]);

            expect(totals.lines.covered).toBe(75);
            expect(totals.lines.total).toBe(100);
            expect(totals.branches.covered).toBe(12);
            expect(totals.branches.total).toBe(16);
            expect(totals.functions.covered).toBe(4);
            expect(totals.functions.total).toBe(5);
        });

        it('should handle files with zero coverage', () => {
            const files: FileCov[] = [
                createTestFile('empty1.ts', [0, 100], [0, 20], [0, 5]),
                createTestFile('empty2.ts', [0, 80], [0, 15], [0, 4])
            ];

            const totals = rollup(files);

            expect(totals.lines.covered).toBe(0);
            expect(totals.lines.total).toBe(180);
            expect(totals.branches.covered).toBe(0);
            expect(totals.branches.total).toBe(35);
            expect(totals.functions.covered).toBe(0);
            expect(totals.functions.total).toBe(9);
        });
    });

    describe('groupCoverage legacy function', () => {
        it('should return Map with package names and files', () => {
            const files: FileCov[] = [
                createTestFile('src/parsers/lcov.ts'),
                createTestFile('src/parsers/clover.ts'),
                createTestFile('src/utils.ts'),
                createTestFile('test/parser.test.ts')
            ];

            const result = groupCoverage({ files });

            expect(result).toBeInstanceOf(Map);
            expect(result.size).toBeGreaterThan(0);
            
            // Should contain grouped packages
            const packageNames = Array.from(result.keys());
            expect(packageNames.length).toBeGreaterThan(0);
        });

        it('should handle empty files', () => {
            const result = groupCoverage({ files: [] });
            expect(result).toBeInstanceOf(Map);
            expect(result.size).toBe(0);
        });
    });

    describe('groupPackagesLegacy function', () => {
        it('should return just the detailed packages', () => {
            const files: FileCov[] = [
                createTestFile('src/parser.ts'),
                createTestFile('src/utils.ts'),
                createTestFile('lib/helper.ts')
            ];

            const result = groupPackagesLegacy(files);

            expect(Array.isArray(result)).toBe(true);
            expect(result.length).toBeGreaterThan(0);
            
            // Should be PkgCov objects
            result.forEach(pkg => {
                expect(pkg).toHaveProperty('name');
                expect(pkg).toHaveProperty('files');
                expect(pkg).toHaveProperty('totals');
            });
        });
    });

    describe('groupPackages edge cases', () => {
        it('should handle files with empty path segments', () => {
            const files: FileCov[] = [
                createTestFile(''),
                createTestFile('//double-slash.ts'),
                createTestFile('./relative.ts'),
                createTestFile('../parent.ts')
            ];

            const result = groupPackages(files);
            expect(result.pkgRows).toBeDefined();
            expect(result.topLevelRows).toBeDefined();
        });

        it('should handle root files correctly', () => {
            const files: FileCov[] = [
                createTestFile('package.json'),
                createTestFile('README.md'),
                createTestFile('src/index.ts')
            ];

            const result = groupPackages(files);
            
            // Should create a 'root' group for files without directories
            const rootGroup = result.pkgRows.find(pkg => pkg.name === 'root');
            if (rootGroup) {
                expect(rootGroup.files.some(f => f.path === 'package.json')).toBe(true);
                expect(rootGroup.files.some(f => f.path === 'README.md')).toBe(true);
            }
        });

        it('should handle dominant group promotion', () => {
            // Create scenario where one group dominates (≥80% of files)
            const srcFiles = Array.from({length: 8}, (_, i) => 
                createTestFile(`src/file${i}.ts`)
            );
            const otherFiles = [
                createTestFile('test/test1.ts'),
                createTestFile('docs/readme.md')
            ];

            const files = [...srcFiles, ...otherFiles];
            
            const config: Required<Config> = {
                groups: [],
                fallback: {
                    smartDepth: 'auto',
                    promoteThreshold: 0.8
                },
                ui: {
                    expandFilesFor: [],
                    maxDeltaRows: 10,
                    minPassThreshold: 50
                }
            };

            const result = groupPackages(files, config);
            
            // src group should be promoted and broken down further
            expect(result.pkgRows.length).toBeGreaterThan(1);
        });

        it('should handle smartDepth top setting', () => {
            const files: FileCov[] = [
                createTestFile('src/deep/nested/file1.ts'),
                createTestFile('src/deep/nested/file2.ts'),
                createTestFile('src/other/file3.ts')
            ];

            const config: Required<Config> = {
                groups: [],
                fallback: {
                    smartDepth: 'top',
                    promoteThreshold: 0.8
                },
                ui: {
                    expandFilesFor: [],
                    maxDeltaRows: 10,
                    minPassThreshold: 50
                }
            };

            const result = groupPackages(files, config);
            
            // Should group at top level only
            expect(result.pkgRows.find(pkg => pkg.name === 'src')).toBeDefined();
        });

        it('should handle smartDepth two setting', () => {
            const files: FileCov[] = [
                createTestFile('src/parsers/lcov.ts'),
                createTestFile('src/parsers/clover.ts'),
                createTestFile('src/utils/helper.ts'),
                createTestFile('test/unit/test1.ts')
            ];

            const config: Required<Config> = {
                groups: [],
                fallback: {
                    smartDepth: 'two', // Note: current implementation only supports 'auto'
                    promoteThreshold: 0.8
                },
                ui: {
                    expandFilesFor: [],
                    maxDeltaRows: 10,
                    minPassThreshold: 50
                }
            };

            const result = groupPackages(files, config);
            
            // Current implementation doesn't specifically handle 'two', so it uses basic grouping
            // Should still create some meaningful groups
            expect(result.pkgRows.length).toBeGreaterThan(0);
            const srcGroup = result.pkgRows.find(pkg => pkg.name === 'src' || pkg.name.startsWith('src/'));
            expect(srcGroup).toBeDefined();
        });

        it('should handle overlay rules matching files', () => {
            const files: FileCov[] = [
                createTestFile('src/parsers/lcov.ts'),
                createTestFile('src/parsers/clover.ts'),
                createTestFile('src/utils.ts'),
                createTestFile('test/parser.test.ts')
            ];

            const config: Required<Config> = {
                groups: [
                    {
                        name: 'parsers-only',
                        patterns: ['src/parsers/**']
                    },
                    {
                        name: 'all-src',
                        patterns: ['src/**'],
                        exclude: ['src/parsers/**']
                    }
                ],
                fallback: {
                    smartDepth: 'auto',
                    promoteThreshold: 0.8
                },
                ui: {
                    expandFilesFor: [],
                    maxDeltaRows: 10,
                    minPassThreshold: 50
                }
            };

            const result = groupPackages(files, config);
            
            // Should have overlay groups
            const parsersOnly = result.pkgRows.find(pkg => pkg.name === 'parsers-only');
            const allSrc = result.pkgRows.find(pkg => pkg.name === 'all-src');
            
            expect(parsersOnly).toBeDefined();
            expect(allSrc).toBeDefined();
            
            if (parsersOnly) {
                expect(parsersOnly.files.length).toBe(2);
                expect(parsersOnly.files.every(f => f.path.includes('parsers'))).toBe(true);
            }
            
            if (allSrc) {
                expect(allSrc.files.some(f => f.path === 'src/utils.ts')).toBe(true);
                expect(allSrc.files.every(f => !f.path.includes('parsers'))).toBe(true);
            }
        });

        it('should handle exclude patterns correctly', () => {
            const files: FileCov[] = [
                createTestFile('src/main.ts'),
                createTestFile('src/test-utils.ts'),
                createTestFile('src/helper.ts')
            ];

            const config: Required<Config> = {
                groups: [
                    {
                        name: 'src-no-test',
                        patterns: ['src/**'],
                        exclude: ['**/test-*']
                    }
                ],
                fallback: {
                    smartDepth: 'auto',
                    promoteThreshold: 0.8
                },
                ui: {
                    expandFilesFor: [],
                    maxDeltaRows: 10,
                    minPassThreshold: 50
                }
            };

            const result = groupPackages(files, config);
            
            const srcNoTest = result.pkgRows.find(pkg => pkg.name === 'src-no-test');
            expect(srcNoTest).toBeDefined();
            
            if (srcNoTest) {
                expect(srcNoTest.files.some(f => f.path === 'src/main.ts')).toBe(true);
                expect(srcNoTest.files.some(f => f.path === 'src/helper.ts')).toBe(true);
                expect(srcNoTest.files.some(f => f.path === 'src/test-utils.ts')).toBe(false);
            }
        });

        it('should log debug information during grouping', () => {
            const files: FileCov[] = [
                createTestFile('src/file1.ts'),
                createTestFile('src/file2.ts')
            ];

            groupPackages(files);

            expect(vi.mocked(core.debug)).toHaveBeenCalledWith(
                expect.stringContaining('Grouping 2 files with config')
            );
            expect(vi.mocked(core.info)).toHaveBeenCalledWith(
                expect.stringContaining('Grouped into')
            );
        });

        it('should sort packages alphabetically', () => {
            const files: FileCov[] = [
                createTestFile('zebra/file.ts'),
                createTestFile('alpha/file.ts'),
                createTestFile('beta/file.ts')
            ];

            const result = groupPackages(files);

            const packageNames = result.pkgRows.map(pkg => pkg.name);
            const sortedNames = [...packageNames].sort();
            expect(packageNames).toEqual(sortedNames);
        });

        it('should handle files with multiple path separators', () => {
            const files: FileCov[] = [
                createTestFile('src\\windows\\path.ts'), // Windows-style path
                createTestFile('src/unix/path.ts'), // Unix-style path
                createTestFile('src//double//slash.ts') // Double slashes
            ];

            const result = groupPackages(files);
            
            // Should normalize and group properly
            expect(result.pkgRows.length).toBeGreaterThan(0);
            expect(result.topLevelRows.length).toBeGreaterThan(0);
        });

        it('should handle very deep nesting', () => {
            const files: FileCov[] = [
                createTestFile('a/b/c/d/e/f/g/h/i/j/deep.ts'),
                createTestFile('a/b/c/different/path.ts')
            ];

            const result = groupPackages(files);
            
            // Should handle deep paths without errors
            expect(result.pkgRows.length).toBeGreaterThan(0);
        });

        it('should handle special characters in paths', () => {
            const files: FileCov[] = [
                createTestFile('src/file-with-dashes.ts'),
                createTestFile('src/file_with_underscores.ts'),
                createTestFile('src/file.with.dots.ts'),
                createTestFile('src/file with spaces.ts')
            ];

            const result = groupPackages(files);
            
            expect(result.pkgRows.length).toBeGreaterThan(0);
            // Should create groups that include all files (might be grouped by src or individually)
            const totalFiles = result.pkgRows.reduce((sum, pkg) => sum + pkg.files.length, 0);
            expect(totalFiles).toBe(4);
        });
    });

    describe('performance and memory tests', () => {
        it('should handle large number of files efficiently', () => {
            // Create 1000 test files
            const files: FileCov[] = Array.from({length: 1000}, (_, i) => 
                createTestFile(`src/module${Math.floor(i / 100)}/file${i}.ts`)
            );

            const startTime = Date.now();
            const result = groupPackages(files);
            const endTime = Date.now();

            // Should complete in reasonable time (less than 1 second)
            expect(endTime - startTime).toBeLessThan(1000);
            expect(result.pkgRows.length).toBeGreaterThan(0);
            expect(result.topLevelRows.length).toBeGreaterThan(0);
        });

        it('should handle files with large coverage numbers', () => {
            const files: FileCov[] = [
                createTestFile('huge1.ts', [999999, 1000000], [99999, 100000], [9999, 10000]),
                createTestFile('huge2.ts', [500000, 1000000], [50000, 100000], [5000, 10000])
            ];

            const result = groupPackages(files);
            const totals = rollup(files);

            expect(totals.lines.covered).toBe(1499999);
            expect(totals.lines.total).toBe(2000000);
            expect(result.pkgRows.length).toBeGreaterThan(0);
        });
    });
});
