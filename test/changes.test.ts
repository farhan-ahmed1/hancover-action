import { describe, it, expect } from 'vitest';
import { 
    computeChangesCoverage, 
    parseGitDiff, 
    computeDeltaCoverage,
    ChangedLinesByFile
} from '../src/changes.js';
import { ProjectCov, PkgCov, FileCov } from '../src/schema.js';

describe('changes', () => {
    describe('computeChangesCoverage', () => {
        it('should compute coverage for changed lines only', () => {
            const file1: FileCov = {
                path: 'src/file1.ts',
                lines: { covered: 8, total: 10 },
                branches: { covered: 4, total: 6 },
                functions: { covered: 2, total: 3 },
                coveredLineNumbers: new Set([1, 2, 3, 5, 6, 7, 8, 10]),
                package: 'src'
            };

            const file2: FileCov = {
                path: 'src/file2.ts',
                lines: { covered: 5, total: 8 },
                branches: { covered: 2, total: 4 },
                functions: { covered: 1, total: 2 },
                coveredLineNumbers: new Set([1, 3, 5, 7, 9]),
                package: 'src'
            };

            const project: ProjectCov = {
                files: [file1, file2],
                totals: {
                    lines: { covered: 13, total: 18 },
                    branches: { covered: 6, total: 10 },
                    functions: { covered: 3, total: 5 }
                }
            };

            const changedLines: ChangedLinesByFile = {
                'src/file1.ts': new Set([2, 4, 6, 8]), // 3 out of 4 covered (2, 6, 8)
                'src/file2.ts': new Set([3, 4, 5, 6])  // 2 out of 4 covered (3, 5)
            };

            const result = computeChangesCoverage(project, changedLines);

            // Should have 2 files in results
            expect(result.files).toHaveLength(2);

            // Check file1 changes coverage
            const changesFile1 = result.files.find(f => f.path === 'src/file1.ts');
            expect(changesFile1).toBeDefined();
            expect(changesFile1!.lines.covered).toBe(3); // lines 2, 6, 8 are covered
            expect(changesFile1!.lines.total).toBe(4);
            expect(changesFile1!.coveredLineNumbers).toEqual(new Set([2, 6, 8]));
            expect(changesFile1!.package).toBe('src');

            // Check file2 changes coverage  
            const changesFile2 = result.files.find(f => f.path === 'src/file2.ts');
            expect(changesFile2).toBeDefined();
            expect(changesFile2!.lines.covered).toBe(2); // lines 3, 5 are covered
            expect(changesFile2!.lines.total).toBe(4);
            expect(changesFile2!.coveredLineNumbers).toEqual(new Set([3, 5]));

            // Check totals
            expect(result.totals.lines.covered).toBe(5); // 3 + 2
            expect(result.totals.lines.total).toBe(8);   // 4 + 4
            expect(result.totals.branches.covered).toBe(0);
            expect(result.totals.branches.total).toBe(0);
            expect(result.totals.functions.covered).toBe(0);
            expect(result.totals.functions.total).toBe(0);

            // Check packages
            expect(result.packages).toHaveLength(1);
            expect(result.packages[0].name).toBe('src');
            expect(result.packages[0].files).toHaveLength(2);
            expect(result.packages[0].totals.lines.covered).toBe(5);
            expect(result.packages[0].totals.lines.total).toBe(8);
        });

        it('should handle files with no changed lines', () => {
            const file: FileCov = {
                path: 'src/file.ts',
                lines: { covered: 5, total: 10 },
                branches: { covered: 2, total: 4 },
                functions: { covered: 1, total: 2 },
                coveredLineNumbers: new Set([1, 2, 3, 4, 5]),
                package: 'src'
            };

            const project: ProjectCov = {
                files: [file],
                totals: {
                    lines: { covered: 5, total: 10 },
                    branches: { covered: 2, total: 4 },
                    functions: { covered: 1, total: 2 }
                }
            };

            const changedLines: ChangedLinesByFile = {
                'src/other-file.ts': new Set([1, 2, 3])
            };

            const result = computeChangesCoverage(project, changedLines);

            expect(result.files).toHaveLength(0);
            expect(result.packages).toHaveLength(0);
            expect(result.totals.lines.covered).toBe(0);
            expect(result.totals.lines.total).toBe(0);
        });

        it('should handle files with empty changed lines set', () => {
            const file: FileCov = {
                path: 'src/file.ts',
                lines: { covered: 5, total: 10 },
                branches: { covered: 2, total: 4 },
                functions: { covered: 1, total: 2 },
                coveredLineNumbers: new Set([1, 2, 3, 4, 5]),
                package: 'src'
            };

            const project: ProjectCov = {
                files: [file],
                totals: {
                    lines: { covered: 5, total: 10 },
                    branches: { covered: 2, total: 4 },
                    functions: { covered: 1, total: 2 }
                }
            };

            const changedLines: ChangedLinesByFile = {
                'src/file.ts': new Set() // empty set
            };

            const result = computeChangesCoverage(project, changedLines);

            expect(result.files).toHaveLength(0);
            expect(result.packages).toHaveLength(0);
            expect(result.totals.lines.covered).toBe(0);
            expect(result.totals.lines.total).toBe(0);
        });

        it('should handle files without package assignment', () => {
            const file: FileCov = {
                path: 'file.ts',
                lines: { covered: 3, total: 5 },
                branches: { covered: 1, total: 2 },
                functions: { covered: 1, total: 1 },
                coveredLineNumbers: new Set([1, 2, 3])
                // no package assigned
            };

            const project: ProjectCov = {
                files: [file],
                totals: {
                    lines: { covered: 3, total: 5 },
                    branches: { covered: 1, total: 2 },
                    functions: { covered: 1, total: 1 }
                }
            };

            const changedLines: ChangedLinesByFile = {
                'file.ts': new Set([1, 2, 4, 5]) // 2 covered, 2 uncovered
            };

            const result = computeChangesCoverage(project, changedLines);

            expect(result.files).toHaveLength(1);
            expect(result.files[0].lines.covered).toBe(2);
            expect(result.files[0].lines.total).toBe(4);
            
            expect(result.packages).toHaveLength(1);
            expect(result.packages[0].name).toBe('root'); // default package name
        });

        it('should group files by package correctly', () => {
            const file1: FileCov = {
                path: 'src/component1.ts',
                lines: { covered: 5, total: 10 },
                branches: { covered: 2, total: 4 },
                functions: { covered: 1, total: 2 },
                coveredLineNumbers: new Set([1, 2, 3, 4, 5]),
                package: 'src'
            };

            const file2: FileCov = {
                path: 'test/component1.test.ts',
                lines: { covered: 8, total: 12 },
                branches: { covered: 3, total: 6 },
                functions: { covered: 2, total: 3 },
                coveredLineNumbers: new Set([1, 2, 3, 4, 5, 6, 7, 8]),
                package: 'test'
            };

            const file3: FileCov = {
                path: 'src/component2.ts',
                lines: { covered: 3, total: 6 },
                branches: { covered: 1, total: 2 },
                functions: { covered: 1, total: 1 },
                coveredLineNumbers: new Set([1, 2, 3]),
                package: 'src'
            };

            const project: ProjectCov = {
                files: [file1, file2, file3],
                totals: {
                    lines: { covered: 16, total: 28 },
                    branches: { covered: 6, total: 12 },
                    functions: { covered: 4, total: 6 }
                }
            };

            const changedLines: ChangedLinesByFile = {
                'src/component1.ts': new Set([1, 6, 7]),     // 1 covered out of 3
                'test/component1.test.ts': new Set([2, 4]),  // 2 covered out of 2
                'src/component2.ts': new Set([1, 4, 5])     // 1 covered out of 3
            };

            const result = computeChangesCoverage(project, changedLines);

            expect(result.packages).toHaveLength(2);
            
            // Check src package
            const srcPackage = result.packages.find(p => p.name === 'src');
            expect(srcPackage).toBeDefined();
            expect(srcPackage!.files).toHaveLength(2);
            expect(srcPackage!.totals.lines.covered).toBe(2); // 1 + 1
            expect(srcPackage!.totals.lines.total).toBe(6);   // 3 + 3

            // Check test package
            const testPackage = result.packages.find(p => p.name === 'test');
            expect(testPackage).toBeDefined();
            expect(testPackage!.files).toHaveLength(1);
            expect(testPackage!.totals.lines.covered).toBe(2);
            expect(testPackage!.totals.lines.total).toBe(2);

            // Packages should be sorted by name
            expect(result.packages[0].name).toBe('src');
            expect(result.packages[1].name).toBe('test');
        });

        it('should handle no changed lines input', () => {
            const file: FileCov = {
                path: 'src/file.ts',
                lines: { covered: 5, total: 10 },
                branches: { covered: 2, total: 4 },
                functions: { covered: 1, total: 2 },
                coveredLineNumbers: new Set([1, 2, 3, 4, 5]),
                package: 'src'
            };

            const project: ProjectCov = {
                files: [file],
                totals: {
                    lines: { covered: 5, total: 10 },
                    branches: { covered: 2, total: 4 },
                    functions: { covered: 1, total: 2 }
                }
            };

            const changedLines: ChangedLinesByFile = {};

            const result = computeChangesCoverage(project, changedLines);

            expect(result.files).toHaveLength(0);
            expect(result.packages).toHaveLength(0);
            expect(result.totals.lines.covered).toBe(0);
            expect(result.totals.lines.total).toBe(0);
        });
    });

    describe('parseGitDiff', () => {
        it('should parse simple git diff output', () => {
            const gitDiff = `diff --git a/src/file1.ts b/src/file1.ts
index abc123..def456 100644
--- a/src/file1.ts
+++ b/src/file1.ts
@@ -10,0 +11,3 @@ export function example() {
+  const newLine1 = true;
+  const newLine2 = false;
+  return newLine1 && newLine2;`;

            const result = parseGitDiff(gitDiff);

            expect(result).toEqual({
                'src/file1.ts': new Set([11, 12, 13])
            });
        });

        it('should parse multiple files in diff', () => {
            const gitDiff = `diff --git a/src/file1.ts b/src/file1.ts
index abc123..def456 100644
--- a/src/file1.ts
+++ b/src/file1.ts
@@ -5,0 +6,2 @@ function test() {
+  return true;
+}
diff --git a/test/file2.test.ts b/test/file2.test.ts
index 789abc..def123 100644
--- a/test/file2.test.ts
+++ b/test/file2.test.ts
@@ -1,0 +2,1 @@ import { expect } from 'vitest';
+describe('test', () => {});`;

            const result = parseGitDiff(gitDiff);

            expect(result).toEqual({
                'src/file1.ts': new Set([6, 7]),
                'test/file2.test.ts': new Set([2])
            });
        });

        it('should parse multiple hunks in same file', () => {
            const gitDiff = `diff --git a/src/file.ts b/src/file.ts
index abc123..def456 100644
--- a/src/file.ts
+++ b/src/file.ts
@@ -5,0 +6,2 @@ function test() {
+  const a = 1;
+  const b = 2;
@@ -20,0 +23,1 @@ function other() {
+  return a + b;`;

            const result = parseGitDiff(gitDiff);

            expect(result).toEqual({
                'src/file.ts': new Set([6, 7, 23])
            });
        });

        it('should handle single line addition', () => {
            const gitDiff = `diff --git a/src/file.ts b/src/file.ts
index abc123..def456 100644
--- a/src/file.ts
+++ b/src/file.ts
@@ -10,0 +11,1 @@ export function example() {
+  return true;`;

            const result = parseGitDiff(gitDiff);

            expect(result).toEqual({
                'src/file.ts': new Set([11])
            });
        });

        it('should handle hunk with no line count (single line)', () => {
            const gitDiff = `diff --git a/src/file.ts b/src/file.ts
index abc123..def456 100644
--- a/src/file.ts
+++ b/src/file.ts
@@ -10,0 +11 @@ export function example() {
+  return true;`;

            const result = parseGitDiff(gitDiff);

            expect(result).toEqual({
                'src/file.ts': new Set([11])
            });
        });

        it('should handle file renames correctly', () => {
            const gitDiff = `diff --git a/old/path.ts b/new/path.ts
similarity index 85%
rename from old/path.ts
rename to new/path.ts
index abc123..def456 100644
--- a/old/path.ts
+++ b/new/path.ts
@@ -5,0 +6,1 @@ function test() {
+  return true;`;

            const result = parseGitDiff(gitDiff);

            expect(result).toEqual({
                'new/path.ts': new Set([6])
            });
        });

        it('should handle empty diff', () => {
            const result = parseGitDiff('');
            expect(result).toEqual({});
        });

        it('should handle diff with no file changes', () => {
            const gitDiff = `diff --git a/README.md b/README.md
index abc123..def456 100644
--- a/README.md
+++ b/README.md`;

            const result = parseGitDiff(gitDiff);
            expect(result).toEqual({ 'README.md': new Set() });
        });

        it('should ignore malformed hunk headers', () => {
            const gitDiff = `diff --git a/src/file.ts b/src/file.ts
index abc123..def456 100644
--- a/src/file.ts
+++ b/src/file.ts
@@ invalid hunk header
+  some content
@@ -10,0 +11,1 @@ valid header
+  return true;`;

            const result = parseGitDiff(gitDiff);

            expect(result).toEqual({
                'src/file.ts': new Set([11])
            });
        });

        it('should handle complex file paths with spaces and special characters', () => {
            const gitDiff = `diff --git a/src/file with spaces.ts b/src/file with spaces.ts
index abc123..def456 100644
--- a/src/file with spaces.ts
+++ b/src/file with spaces.ts
@@ -1,0 +2,1 @@ export function test() {
+  return 'hello world';`;

            const result = parseGitDiff(gitDiff);

            expect(result).toEqual({
                'src/file with spaces.ts': new Set([2])
            });
        });

        it('should handle larger line ranges', () => {
            const gitDiff = `diff --git a/src/file.ts b/src/file.ts
index abc123..def456 100644
--- a/src/file.ts
+++ b/src/file.ts
@@ -10,0 +11,10 @@ export function example() {
+  const line1 = 1;
+  const line2 = 2;
+  const line3 = 3;
+  const line4 = 4;
+  const line5 = 5;
+  const line6 = 6;
+  const line7 = 7;
+  const line8 = 8;
+  const line9 = 9;
+  const line10 = 10;`;

            const result = parseGitDiff(gitDiff);

            expect(result).toEqual({
                'src/file.ts': new Set([11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
            });
        });
    });

    describe('computeDeltaCoverage', () => {
        it('should compute delta coverage between PR and main', () => {
            const prPackages: PkgCov[] = [
                {
                    name: 'src',
                    files: [],
                    totals: {
                        lines: { covered: 85, total: 100 },    // 85%
                        branches: { covered: 40, total: 50 },  // 80%
                        functions: { covered: 9, total: 10 }   // 90%
                    }
                },
                {
                    name: 'test',
                    files: [],
                    totals: {
                        lines: { covered: 48, total: 60 },     // 80%
                        branches: { covered: 15, total: 20 },  // 75%
                        functions: { covered: 5, total: 8 }    // 62.5%
                    }
                }
            ];

            const mainPackages: PkgCov[] = [
                {
                    name: 'src',
                    files: [],
                    totals: {
                        lines: { covered: 80, total: 100 },    // 80%
                        branches: { covered: 35, total: 50 },  // 70%
                        functions: { covered: 8, total: 10 }   // 80%
                    }
                },
                {
                    name: 'test',
                    files: [],
                    totals: {
                        lines: { covered: 54, total: 60 },     // 90%
                        branches: { covered: 18, total: 20 },  // 90%
                        functions: { covered: 6, total: 8 }    // 75%
                    }
                }
            ];

            const result = computeDeltaCoverage(prPackages, mainPackages);

            expect(result.packages).toHaveLength(2);

            // Check src package (should be first due to larger absolute delta)
            const srcPackage = result.packages.find(p => p.name === 'src');
            expect(srcPackage).toBeDefined();
            expect(srcPackage!.linesDeltas.pr).toBeCloseTo(85, 1);
            expect(srcPackage!.linesDeltas.main).toBeCloseTo(80, 1);
            expect(srcPackage!.linesDeltas.delta).toBeCloseTo(5, 1);
            expect(srcPackage!.branchesDeltas.pr).toBeCloseTo(80, 1);
            expect(srcPackage!.branchesDeltas.main).toBeCloseTo(70, 1);
            expect(srcPackage!.branchesDeltas.delta).toBeCloseTo(10, 1);
            expect(srcPackage!.functionsDeltas.pr).toBeCloseTo(90, 1);
            expect(srcPackage!.functionsDeltas.main).toBeCloseTo(80, 1);
            expect(srcPackage!.functionsDeltas.delta).toBeCloseTo(10, 1);

            // Check test package
            const testPackage = result.packages.find(p => p.name === 'test');
            expect(testPackage).toBeDefined();
            expect(testPackage!.linesDeltas.pr).toBeCloseTo(80, 1);
            expect(testPackage!.linesDeltas.main).toBeCloseTo(90, 1);
            expect(testPackage!.linesDeltas.delta).toBeCloseTo(-10, 1);
            expect(testPackage!.branchesDeltas.pr).toBeCloseTo(75, 1);
            expect(testPackage!.branchesDeltas.main).toBeCloseTo(90, 1);
            expect(testPackage!.branchesDeltas.delta).toBeCloseTo(-15, 1);
            expect(testPackage!.functionsDeltas.pr).toBeCloseTo(62.5, 1);
            expect(testPackage!.functionsDeltas.main).toBeCloseTo(75, 1);
            expect(testPackage!.functionsDeltas.delta).toBeCloseTo(-12.5, 1);
        });

        it('should handle packages only in PR', () => {
            const prPackages: PkgCov[] = [
                {
                    name: 'new-package',
                    files: [],
                    totals: {
                        lines: { covered: 50, total: 100 },
                        branches: { covered: 25, total: 50 },
                        functions: { covered: 5, total: 10 }
                    }
                }
            ];

            const mainPackages: PkgCov[] = [];

            const result = computeDeltaCoverage(prPackages, mainPackages);

            expect(result.packages).toHaveLength(1);
            const newPackage = result.packages[0];
            expect(newPackage.name).toBe('new-package');
            expect(newPackage.linesDeltas.pr).toBeCloseTo(50, 1);
            expect(newPackage.linesDeltas.main).toBe(0);
            expect(newPackage.linesDeltas.delta).toBeCloseTo(50, 1);
        });

        it('should handle packages only in main', () => {
            const prPackages: PkgCov[] = [];

            const mainPackages: PkgCov[] = [
                {
                    name: 'removed-package',
                    files: [],
                    totals: {
                        lines: { covered: 80, total: 100 },
                        branches: { covered: 40, total: 50 },
                        functions: { covered: 8, total: 10 }
                    }
                }
            ];

            const result = computeDeltaCoverage(prPackages, mainPackages);

            expect(result.packages).toHaveLength(1);
            const removedPackage = result.packages[0];
            expect(removedPackage.name).toBe('removed-package');
            expect(removedPackage.linesDeltas.pr).toBe(0);
            expect(removedPackage.linesDeltas.main).toBeCloseTo(80, 1);
            expect(removedPackage.linesDeltas.delta).toBeCloseTo(-80, 1);
        });

        it('should handle packages with zero totals', () => {
            const prPackages: PkgCov[] = [
                {
                    name: 'empty-package',
                    files: [],
                    totals: {
                        lines: { covered: 0, total: 0 },
                        branches: { covered: 0, total: 0 },
                        functions: { covered: 0, total: 0 }
                    }
                }
            ];

            const mainPackages: PkgCov[] = [
                {
                    name: 'empty-package',
                    files: [],
                    totals: {
                        lines: { covered: 0, total: 0 },
                        branches: { covered: 0, total: 0 },
                        functions: { covered: 0, total: 0 }
                    }
                }
            ];

            const result = computeDeltaCoverage(prPackages, mainPackages);

            expect(result.packages).toHaveLength(1);
            const emptyPackage = result.packages[0];
            expect(emptyPackage.linesDeltas.pr).toBe(100); // pct() returns 100 when total is 0
            expect(emptyPackage.linesDeltas.main).toBe(100);
            expect(emptyPackage.linesDeltas.delta).toBe(0);
        });

        it('should sort packages by absolute delta descending', () => {
            const prPackages: PkgCov[] = [
                {
                    name: 'package-a',
                    files: [],
                    totals: { lines: { covered: 55, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                },
                {
                    name: 'package-b',
                    files: [],
                    totals: { lines: { covered: 85, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                },
                {
                    name: 'package-c',
                    files: [],
                    totals: { lines: { covered: 70, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                }
            ];

            const mainPackages: PkgCov[] = [
                {
                    name: 'package-a',
                    files: [],
                    totals: { lines: { covered: 50, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                },
                {
                    name: 'package-b',
                    files: [],
                    totals: { lines: { covered: 70, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                },
                {
                    name: 'package-c',
                    files: [],
                    totals: { lines: { covered: 80, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                }
            ];

            const result = computeDeltaCoverage(prPackages, mainPackages);

            // Deltas: package-a = +5, package-b = +15, package-c = -10
            // Sorted by absolute delta: package-b (15), package-c (10), package-a (5)
            expect(result.packages[0].name).toBe('package-b');
            expect(result.packages[1].name).toBe('package-c');
            expect(result.packages[2].name).toBe('package-a');
        });

        it('should handle empty inputs', () => {
            const result = computeDeltaCoverage([], []);
            expect(result.packages).toHaveLength(0);
        });

        it('should handle mixed packages correctly', () => {
            const prPackages: PkgCov[] = [
                {
                    name: 'common',
                    files: [],
                    totals: { lines: { covered: 60, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                },
                {
                    name: 'new-in-pr',
                    files: [],
                    totals: { lines: { covered: 80, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                }
            ];

            const mainPackages: PkgCov[] = [
                {
                    name: 'common',
                    files: [],
                    totals: { lines: { covered: 70, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                },
                {
                    name: 'removed-in-pr',
                    files: [],
                    totals: { lines: { covered: 90, total: 100 }, branches: { covered: 0, total: 0 }, functions: { covered: 0, total: 0 } }
                }
            ];

            const result = computeDeltaCoverage(prPackages, mainPackages);

            expect(result.packages).toHaveLength(3);

            const commonPackage = result.packages.find(p => p.name === 'common');
            expect(commonPackage!.linesDeltas.delta).toBeCloseTo(-10, 1);

            const newPackage = result.packages.find(p => p.name === 'new-in-pr');
            expect(newPackage!.linesDeltas.delta).toBeCloseTo(80, 1);

            const removedPackage = result.packages.find(p => p.name === 'removed-in-pr');
            expect(removedPackage!.linesDeltas.delta).toBeCloseTo(-90, 1);
        });
    });
});
