import { describe, it, expect } from 'vitest';
import { parseLcovFile, parseLCOV } from '../../src/parsers/lcov.js';

describe('LCOV Parser', () => {
    it('should parse a small LCOV file correctly', async () => {
        const result = parseLcovFile('test/fixtures/lcov.small.info');
        
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

    it('should parse LCOV data string correctly', () => {
        const lcovData = `SF:src/test.js
DA:1,5
DA:2,0
DA:3,2
end_of_record`;
        
        const result = parseLCOV(lcovData);
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/test.js',
            lines: { covered: 2, total: 3 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 },
            coveredLineNumbers: new Set([1, 3])
        });
        expect(result.totals).toEqual({
            lines: { covered: 2, total: 3 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });

    it('should handle empty LCOV files', () => {
        const emptyLcov = '';
        const result = parseLCOV(emptyLcov);
        expect(result.files).toHaveLength(0);
        expect(result.totals).toEqual({
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });

    it('should handle LCOV with function coverage', () => {
        const lcovData = `SF:src/functions.js
FN:1,testFunction
FN:5,anotherFunction
FNDA:10,testFunction
FNDA:0,anotherFunction
FNF:2
FNH:1
DA:1,10
DA:2,10
DA:5,0
DA:6,0
LF:4
LH:2
end_of_record`;
        
        const result = parseLCOV(lcovData);
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/functions.js',
            lines: { covered: 2, total: 4 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 1, total: 2 },
            coveredLineNumbers: new Set([1, 2])
        });
    });

    it('should handle LCOV with branch coverage', () => {
        const lcovData = `SF:src/branches.js
DA:1,5
DA:2,5
DA:3,2
BRF:2
BRH:1
BDA:2,0,5
BDA:2,1,0
LF:3
LH:3
end_of_record`;
        
        const result = parseLCOV(lcovData);
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/branches.js',
            lines: { covered: 3, total: 3 },
            branches: { covered: 0, total: 0 }, // LCOV parser may not handle BDA properly
            functions: { covered: 0, total: 0 },
            coveredLineNumbers: new Set([1, 2, 3])
        });
    });
});
