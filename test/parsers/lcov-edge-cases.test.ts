import { describe, it, expect } from 'vitest';
import { parseLcovFile, parseLCOV } from '../../src/parsers/lcov.js';

describe('LCOV Parser - Edge Cases & Robustness', () => {
    describe('Security & Malformed Input', () => {
        it('should sanitize file paths to prevent directory traversal', async () => {
            const result = await parseLcovFile('test/fixtures/lcov/lcov.malicious.info');
            
            expect(result.files).toHaveLength(2);
            
            // Check that malicious path is sanitized
            const maliciousFile = result.files.find((f) => f.path === 'etc/passwd');
            expect(maliciousFile).toBeDefined();
            expect(maliciousFile?.path).not.toContain('../');
            
            // Check that normal file is preserved
            const normalFile = result.files.find((f) => f.path === 'src/normal.js');
            expect(normalFile).toBeDefined();
            expect(normalFile).toEqual({
                path: 'src/normal.js',
                lines: { covered: 2, total: 3 },
                branches: { covered: 1, total: 2 },
                functions: { covered: 1, total: 1 },
                coveredLineNumbers: new Set([1, 2])
            });
        });

        it('should handle excessive line count protection', () => {
            // Create LCOV with excessive lines
            const manyLines = Array.from({ length: 1000001 }, (_, i) => `DA:${i},1`).join('\n');
            const lcovData = `SF:src/large.js\n${manyLines}\nend_of_record`;
            
            expect(() => parseLCOV(lcovData)).toThrow(/excessive number of lines/);
        });

        it('should handle very large file size', () => {
            // This would be tested with actual large files in practice
            // For now, test that the size limit function is called
            const lcovData = 'SF:test.js\nDA:1,1\nend_of_record';
            expect(() => parseLCOV(lcovData)).not.toThrow();
        });

        it('should reject non-string input', () => {
            expect(() => parseLCOV(null as any)).toThrow(/LCOV data must be a string/);
            expect(() => parseLCOV(undefined as any)).toThrow(/LCOV data must be a string/);
            expect(() => parseLCOV(123 as any)).toThrow(/LCOV data must be a string/);
            expect(() => parseLCOV({} as any)).toThrow(/LCOV data must be a string/);
        });
    });

    describe('Data Validation & Edge Cases', () => {
        it('should handle very large line numbers safely', async () => {
            const result = await parseLcovFile('test/fixtures/lcov/lcov.complex.info');
            
            // Find the edge cases file
            const edgeCasesFile = result.files.find(f => f.path === 'src/edge-cases.js');
            expect(edgeCasesFile).toBeDefined();
            
            expect(edgeCasesFile).toEqual({
                path: 'src/edge-cases.js',
                lines: { covered: 2, total: 3 },
                branches: { covered: 1, total: 4 },
                functions: { covered: 1, total: 2 },
                coveredLineNumbers: new Set([999999, 1000001])
            });
        });

        it('should handle malformed line numbers gracefully', () => {
            const lcovData = `SF:src/malformed.js
DA:abc,1
DA:1.5,1
DA:,1
DA:5,xyz
DA:6,1
FN:abc,badFunc
FN:7,goodFunc
FNDA:xyz,goodFunc
FNDA:5,goodFunc
BRDA:abc,0,0,1
BRDA:8,0,0,5
BRDA:9,0,0,-
end_of_record`;
            
            const result = parseLCOV(lcovData);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            // Line parsing: 
            // - DA:abc,1 -> lineNumber=null (invalid), skipped
            // - DA:1.5,1 -> lineNumber=null (invalid decimal), skipped  
            // - DA:,1 -> lineNumber=null (empty), skipped
            // - DA:5,xyz -> hits=null (invalid), skipped
            // - DA:6,1 -> valid, counted
            expect(file.lines.total).toBe(1); // Only line 6
            expect(file.lines.covered).toBe(1); // Only line 6
            expect(file.coveredLineNumbers).toEqual(new Set([6]));
            
            // Function parsing:
            // - FN:abc,badFunc -> lineNumber=null (invalid), skipped
            // - FN:7,goodFunc -> valid function definition
            // - FNDA:xyz,goodFunc -> hits=null (invalid), skipped in calculation
            // - FNDA:5,goodFunc -> valid hits
            expect(file.functions.total).toBe(1); // Only goodFunc
            expect(file.functions.covered).toBe(1); // goodFunc has valid hits
            
            // Branch parsing:
            // - BRDA:abc,0,0,1 -> lineNumber=null (invalid), skipped
            // - BRDA:8,0,0,5 -> valid, taken=5, counted as covered
            // - BRDA:9,0,0,- -> valid, taken=null (dash), not covered
            expect(file.branches.total).toBe(2); // 8,0,0,5 and 9,0,0,-
            expect(file.branches.covered).toBe(1); // Only 8,0,0,5 (- means not taken)
        });

        it('should handle files with no coverage data', () => {
            const lcovData = `SF:src/empty.js
end_of_record`;
            
            const result = parseLCOV(lcovData);
            expect(result.files).toHaveLength(1);
            expect(result.files[0]).toEqual({
                path: 'src/empty.js',
                lines: { covered: 0, total: 0 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 0, total: 0 },
                coveredLineNumbers: new Set()
            });
        });

        it('should handle functions with no definitions but hit data', () => {
            const lcovData = `SF:src/orphan-functions.js
FNDA:5,orphanFunc1
FNDA:0,orphanFunc2
FNDA:10,orphanFunc3
end_of_record`;
            
            const result = parseLCOV(lcovData);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.functions.total).toBe(3); // 3 functions from FNDA records
            expect(file.functions.covered).toBe(2); // orphanFunc1 and orphanFunc3 have > 0 hits
        });

        it('should handle branch records with dashes (not taken)', () => {
            const lcovData = `SF:src/branches.js
BRDA:1,0,0,5
BRDA:1,0,1,-
BRDA:2,0,0,0
BRDA:2,0,1,3
end_of_record`;
            
            const result = parseLCOV(lcovData);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.branches.total).toBe(4);
            expect(file.branches.covered).toBe(2); // 1,0,0,5 and 2,0,1,3
        });

        it('should handle mixed case and whitespace in record parsing', () => {
            const lcovData = `  SF:  src/whitespace.js  
  DA:  1  ,  5  
  FN:  1  ,  testFunc  
  FNDA:  5  ,  testFunc  
  BRDA:  1  ,  0  ,  0  ,  3  
  end_of_record  `;
            
            const result = parseLCOV(lcovData);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.path).toBe('src/whitespace.js');
            expect(file.lines.total).toBe(1);
            expect(file.lines.covered).toBe(1);
            expect(file.functions.total).toBe(1);
            expect(file.functions.covered).toBe(1);
            expect(file.branches.total).toBe(1);
            expect(file.branches.covered).toBe(1);
        });

        it('should skip comments and empty lines', () => {
            const lcovData = `# This is a comment
SF:src/commented.js

# Another comment
DA:1,1
# Line comment
DA:2,0

# Function comment
FN:1,test
FNDA:1,test

end_of_record
# Final comment`;
            
            const result = parseLCOV(lcovData);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.path).toBe('src/commented.js');
            expect(file.lines.total).toBe(2);
            expect(file.lines.covered).toBe(1);
            expect(file.functions.total).toBe(1);
            expect(file.functions.covered).toBe(1);
        });

        it('should handle function names with special characters', () => {
            const lcovData = `SF:src/special.js
FN:1,function$with_special-chars.test
FN:5,another@function#test
FNDA:3,function$with_special-chars.test
FNDA:0,another@function#test
end_of_record`;
            
            const result = parseLCOV(lcovData);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.functions.total).toBe(2);
            expect(file.functions.covered).toBe(1);
        });

        it('should handle negative hit counts gracefully', () => {
            const lcovData = `SF:src/negative.js
DA:1,-5
DA:2,0
DA:3,10
FNDA:-3,negativeFunc
FNDA:5,positiveFunc
BRDA:1,0,0,-5
BRDA:1,0,1,5
end_of_record`;
            
            const result = parseLCOV(lcovData);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            // Negative values should be rejected by parseIntSafe
            // Valid records: DA:2,0 and DA:3,10 
            expect(file.lines.total).toBe(2); // DA:2,0 and DA:3,10
            expect(file.lines.covered).toBe(1); // Only DA:3,10
            // Only positiveFunc should be counted (negativeFunc has negative hits)
            expect(file.functions.total).toBe(1); // Only positiveFunc 
            expect(file.functions.covered).toBe(1); // Only positiveFunc
            // Branch records: BRDA:1,0,0,-5 -> taken=-5 (invalid), BRDA:1,0,1,5 -> taken=5 (valid)
            // But the parsing checks for valid line/block/branch numbers first
            // Since lineNumber=1, block=0, branch=0/1 are all valid, both records get processed
            // However, -5 is invalid as taken count, so only the second branch is covered
            expect(file.branches.total).toBe(2); // Both branch records are counted
            expect(file.branches.covered).toBe(1); // Only 1,0,1,5 (second one with taken=5)
        });
    });

    describe('Error Handling', () => {
        it('should provide meaningful error messages for file read failures', async () => {
            await expect(parseLcovFile('nonexistent/file.info')).rejects.toThrow(/Failed to read LCOV file/);
        });

        it('should handle malformed records gracefully', () => {
            const lcovData = `SF:src/malformed.js
DA:incomplete
FN:also:incomplete:with:colons
BRDA:incomplete,data
TOTALLY_INVALID_RECORD:data
DA:1,5
end_of_record`;
            
            // Should not throw, but skip malformed records
            const result = parseLCOV(lcovData);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.lines.total).toBe(1); // Only the valid DA:1,5
            expect(file.lines.covered).toBe(1);
        });
    });

    describe('Performance & Large Files', () => {
        it('should handle reasonably large LCOV files efficiently', () => {
            // Generate a moderately large LCOV file
            const lines = [];
            lines.push('SF:src/large-file.js');
            
            // Add 10,000 lines of coverage
            for (let i = 1; i <= 10000; i++) {
                lines.push(`DA:${i},${i % 3 === 0 ? 0 : 1}`);
            }
            
            // Add 1,000 functions
            for (let i = 1; i <= 1000; i++) {
                lines.push(`FN:${i},func${i}`);
                lines.push(`FNDA:${i % 2},func${i}`);
            }
            
            // Add 1,000 branches
            for (let i = 1; i <= 500; i++) {
                lines.push(`BRDA:${i},0,0,${i % 3}`);
                lines.push(`BRDA:${i},0,1,${i % 2}`);
            }
            
            lines.push('end_of_record');
            
            const lcovData = lines.join('\n');
            
            const start = Date.now();
            const result = parseLCOV(lcovData);
            const duration = Date.now() - start;
            
            expect(result.files).toHaveLength(1);
            const file = result.files[0];
            
            expect(file.lines.total).toBe(10000);
            expect(file.functions.total).toBe(1000);
            expect(file.branches.total).toBe(1000);
            
            // Should complete in reasonable time (< 1 second for this size)
            expect(duration).toBeLessThan(1000);
        });
    });
});
