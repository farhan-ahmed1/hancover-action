import { describe, it, expect } from 'vitest';
import { parseLcovFile, parseLCOV } from '../../src/parsers/lcov.js';

describe('LCOV Parser - Core Functionality', () => {
    it('should parse a small LCOV file correctly', () => {
        const result = parseLcovFile('test/fixtures/lcov/lcov.small.info');
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'sample/file/path',
            lines: { covered: 7, total: 10 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 },
            coveredLineNumbers: new Set([1, 3, 4, 6, 7, 8, 10])
        });
        expect(result.totals).toEqual({
            lines: { covered: 7, total: 10 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });

    it('should parse complex LCOV file with multiple files and full coverage data', () => {
        const result = parseLcovFile('test/fixtures/lcov/lcov.sample.info');
        
        expect(result.files).toHaveLength(3);
        
        // Check calculator.js
        const calculatorFile = result.files.find(f => f.path === 'src/calculator.js');
        expect(calculatorFile).toBeDefined();
        expect(calculatorFile).toEqual({
            path: 'src/calculator.js',
            lines: { covered: 8, total: 11 },
            branches: { covered: 6, total: 8 },
            functions: { covered: 3, total: 4 },
            coveredLineNumbers: new Set([1, 2, 3, 10, 11, 12, 20, 21])
        });
        
        // Check utils.js
        const utilsFile = result.files.find(f => f.path === 'src/utils.js');
        expect(utilsFile).toBeDefined();
        expect(utilsFile).toEqual({
            path: 'src/utils.js',
            lines: { covered: 8, total: 8 },
            branches: { covered: 4, total: 4 },
            functions: { covered: 2, total: 2 },
            coveredLineNumbers: new Set([5, 6, 7, 8, 15, 16, 17, 18])
        });
        
        // Check test file
        const testFile = result.files.find(f => f.path === 'tests/calculator.test.js');
        expect(testFile).toBeDefined();
        expect(testFile).toEqual({
            path: 'tests/calculator.test.js',
            lines: { covered: 10, total: 10 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 3, total: 3 },
            coveredLineNumbers: new Set([1, 2, 3, 4, 10, 11, 12, 20, 21, 22])
        });
        
        // Check totals
        expect(result.totals).toEqual({
            lines: { covered: 26, total: 29 },
            branches: { covered: 10, total: 12 },
            functions: { covered: 8, total: 9 }
        });
    });

    it('should parse LCOV data string correctly', () => {
        const lcovData = `SF:src/test.js
FN:1,testFunction
FNDA:5,testFunction
FNF:1
FNH:1
DA:1,5
DA:2,0
DA:3,2
LF:3
LH:2
BRDA:1,0,0,3
BRDA:1,0,1,2
BRF:2
BRH:2
end_of_record`;
        
        const result = parseLCOV(lcovData);
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/test.js',
            lines: { covered: 2, total: 3 },
            branches: { covered: 2, total: 2 },
            functions: { covered: 1, total: 1 },
            coveredLineNumbers: new Set([1, 3])
        });
        expect(result.totals).toEqual({
            lines: { covered: 2, total: 3 },
            branches: { covered: 2, total: 2 },
            functions: { covered: 1, total: 1 }
        });
    });

    it('should handle empty LCOV files', () => {
        const result = parseLcovFile('test/fixtures/lcov/lcov.empty.info');
        expect(result.files).toHaveLength(0);
        expect(result.totals).toEqual({
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });

    it('should handle LCOV with function coverage only', () => {
        const lcovData = `SF:src/functions.js
FN:1,testFunction
FN:5,anotherFunction
FNDA:10,testFunction
FNDA:0,anotherFunction
FNF:2
FNH:1
end_of_record`;
        
        const result = parseLCOV(lcovData);
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/functions.js',
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 1, total: 2 },
            coveredLineNumbers: new Set()
        });
    });

    it('should handle LCOV with branch coverage only', () => {
        const lcovData = `SF:src/branches.js
BRDA:1,0,0,5
BRDA:1,0,1,0
BRDA:2,0,0,3
BRDA:2,0,1,2
BRF:4
BRH:3
end_of_record`;
        
        const result = parseLCOV(lcovData);
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/branches.js',
            lines: { covered: 0, total: 0 },
            branches: { covered: 3, total: 4 },
            functions: { covered: 0, total: 0 },
            coveredLineNumbers: new Set()
        });
    });

    it('should handle files without end_of_record marker', () => {
        const lcovData = `SF:src/no-end.js
DA:1,1
DA:2,0
FN:1,test
FNDA:1,test`;
        
        const result = parseLCOV(lcovData);
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/no-end.js',
            lines: { covered: 1, total: 2 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 1, total: 1 },
            coveredLineNumbers: new Set([1])
        });
    });

    it('should handle multiple files with mixed coverage data', () => {
        const lcovData = `SF:src/file1.js
DA:1,5
DA:2,0
end_of_record
SF:src/file2.js
FN:1,func
FNDA:3,func
BRDA:1,0,0,2
BRDA:1,0,1,1
end_of_record`;
        
        const result = parseLCOV(lcovData);
        expect(result.files).toHaveLength(2);
        
        expect(result.files[0]).toEqual({
            path: 'src/file1.js',
            lines: { covered: 1, total: 2 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 },
            coveredLineNumbers: new Set([1])
        });
        
        expect(result.files[1]).toEqual({
            path: 'src/file2.js',
            lines: { covered: 0, total: 0 },
            branches: { covered: 2, total: 2 },
            functions: { covered: 1, total: 1 },
            coveredLineNumbers: new Set()
        });
    });
});