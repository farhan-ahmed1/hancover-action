import { describe, it, expect } from 'vitest';
import { FileCov, ProjectCov, PkgCov, CoverageBundle, ExpandablePackage } from '../src/schema.js';

describe('Schema Type Validation', () => {
    describe('FileCov', () => {
        it('should validate FileCov structure', () => {
            const validFileCov: FileCov = {
                path: 'src/test.ts',
                lines: { covered: 80, total: 100 },
                branches: { covered: 15, total: 20 },
                functions: { covered: 5, total: 5 },
                coveredLineNumbers: new Set([1, 2, 3, 4, 5]),
                package: 'test-package'
            };

            // Type check - if this compiles, the type is valid
            expect(validFileCov.path).toBe('src/test.ts');
            expect(validFileCov.lines.covered).toBe(80);
            expect(validFileCov.lines.total).toBe(100);
            expect(validFileCov.branches.covered).toBe(15);
            expect(validFileCov.branches.total).toBe(20);
            expect(validFileCov.functions.covered).toBe(5);
            expect(validFileCov.functions.total).toBe(5);
            expect(validFileCov.coveredLineNumbers).toBeInstanceOf(Set);
            expect(validFileCov.coveredLineNumbers.has(1)).toBe(true);
            expect(validFileCov.package).toBe('test-package');
        });

        it('should allow optional package field', () => {
            const fileCovWithoutPackage: FileCov = {
                path: 'src/test.ts',
                lines: { covered: 80, total: 100 },
                branches: { covered: 15, total: 20 },
                functions: { covered: 5, total: 5 },
                coveredLineNumbers: new Set([1, 2, 3])
            };

            expect(fileCovWithoutPackage.package).toBeUndefined();
        });

        it('should handle empty Set for coveredLineNumbers', () => {
            const fileCovEmptyLines: FileCov = {
                path: 'src/empty.ts',
                lines: { covered: 0, total: 10 },
                branches: { covered: 0, total: 5 },
                functions: { covered: 0, total: 2 },
                coveredLineNumbers: new Set()
            };

            expect(fileCovEmptyLines.coveredLineNumbers.size).toBe(0);
        });
    });

    describe('ProjectCov', () => {
        it('should validate ProjectCov structure', () => {
            const fileCov: FileCov = {
                path: 'src/test.ts',
                lines: { covered: 80, total: 100 },
                branches: { covered: 15, total: 20 },
                functions: { covered: 5, total: 5 },
                coveredLineNumbers: new Set([1, 2, 3])
            };

            const validProjectCov: ProjectCov = {
                files: [fileCov],
                totals: {
                    lines: { covered: 80, total: 100 },
                    branches: { covered: 15, total: 20 },
                    functions: { covered: 5, total: 5 }
                }
            };

            expect(validProjectCov.files).toHaveLength(1);
            expect(validProjectCov.files[0]).toEqual(fileCov);
            expect(validProjectCov.totals.lines.covered).toBe(80);
            expect(validProjectCov.totals.branches.covered).toBe(15);
            expect(validProjectCov.totals.functions.covered).toBe(5);
        });

        it('should handle empty files array', () => {
            const emptyProjectCov: ProjectCov = {
                files: [],
                totals: {
                    lines: { covered: 0, total: 0 },
                    branches: { covered: 0, total: 0 },
                    functions: { covered: 0, total: 0 }
                }
            };

            expect(emptyProjectCov.files).toHaveLength(0);
        });
    });

    describe('PkgCov', () => {
        it('should validate PkgCov structure', () => {
            const fileCov: FileCov = {
                path: 'src/parser.ts',
                lines: { covered: 90, total: 100 },
                branches: { covered: 18, total: 20 },
                functions: { covered: 7, total: 8 },
                coveredLineNumbers: new Set([1, 2, 3, 4])
            };

            const validPkgCov: PkgCov = {
                name: 'parsers',
                files: [fileCov],
                totals: {
                    lines: { covered: 90, total: 100 },
                    branches: { covered: 18, total: 20 },
                    functions: { covered: 7, total: 8 }
                }
            };

            expect(validPkgCov.name).toBe('parsers');
            expect(validPkgCov.files).toHaveLength(1);
            expect(validPkgCov.totals.lines.covered).toBe(90);
        });
    });

    describe('CoverageBundle', () => {
        it('should validate CoverageBundle structure', () => {
            const fileCov: FileCov = {
                path: 'src/bundle.ts',
                lines: { covered: 75, total: 100 },
                branches: { covered: 12, total: 16 },
                functions: { covered: 4, total: 6 },
                coveredLineNumbers: new Set([1, 2, 5, 7])
            };

            const validBundle: CoverageBundle = {
                files: [fileCov]
            };

            expect(validBundle.files).toHaveLength(1);
            expect(validBundle.files[0].path).toBe('src/bundle.ts');
        });
    });

    describe('ExpandablePackage', () => {
        it('should validate ExpandablePackage structure', () => {
            const fileCov: FileCov = {
                path: 'src/expandable.ts',
                lines: { covered: 95, total: 100 },
                branches: { covered: 19, total: 20 },
                functions: { covered: 8, total: 8 },
                coveredLineNumbers: new Set([1, 2, 3, 4, 5])
            };

            const expandablePackage: ExpandablePackage = {
                name: 'expandable',
                files: [fileCov],
                totals: {
                    lines: { covered: 95, total: 100 },
                    branches: { covered: 19, total: 20 },
                    functions: { covered: 8, total: 8 }
                },
                shouldExpand: true
            };

            expect(expandablePackage.name).toBe('expandable');
            expect(expandablePackage.shouldExpand).toBe(true);
            expect(expandablePackage.files).toHaveLength(1);
        });

        it('should handle shouldExpand false', () => {
            const fileCov: FileCov = {
                path: 'src/collapsed.ts',
                lines: { covered: 60, total: 100 },
                branches: { covered: 10, total: 20 },
                functions: { covered: 3, total: 5 },
                coveredLineNumbers: new Set([1, 3, 5])
            };

            const collapsedPackage: ExpandablePackage = {
                name: 'collapsed',
                files: [fileCov],
                totals: {
                    lines: { covered: 60, total: 100 },
                    branches: { covered: 10, total: 20 },
                    functions: { covered: 3, total: 5 }
                },
                shouldExpand: false
            };

            expect(collapsedPackage.shouldExpand).toBe(false);
        });
    });

    describe('Type compatibility tests', () => {
        it('should ensure Set<number> behaves correctly for coveredLineNumbers', () => {
            const lineNumbers = new Set<number>([1, 2, 3, 2, 1]); // Duplicates should be removed
            
            expect(lineNumbers.size).toBe(3);
            expect(lineNumbers.has(1)).toBe(true);
            expect(lineNumbers.has(2)).toBe(true);
            expect(lineNumbers.has(3)).toBe(true);
            expect(lineNumbers.has(4)).toBe(false);
            
            // Test iteration
            const sortedNumbers = Array.from(lineNumbers).sort((a, b) => a - b);
            expect(sortedNumbers).toEqual([1, 2, 3]);
        });

        it('should handle percentage calculations correctly', () => {
            const fileCov: FileCov = {
                path: 'src/calc.ts',
                lines: { covered: 85, total: 100 },
                branches: { covered: 17, total: 20 },
                functions: { covered: 9, total: 10 },
                coveredLineNumbers: new Set(Array.from({length: 85}, (_, i) => i + 1))
            };

            const linePercentage = (fileCov.lines.covered / fileCov.lines.total) * 100;
            const branchPercentage = (fileCov.branches.covered / fileCov.branches.total) * 100;
            const functionPercentage = (fileCov.functions.covered / fileCov.functions.total) * 100;

            expect(linePercentage).toBe(85);
            expect(branchPercentage).toBe(85);
            expect(functionPercentage).toBe(90);
        });
    });
});
