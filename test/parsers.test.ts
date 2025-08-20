import { describe, it, expect } from 'vitest';
import { parseLcovFile, parseLCOV } from '../src/parsers/lcov.js';
import { parseCobertura } from '../src/parsers/cobertura.js';
import { parseClover, parseCloverFile } from '../src/parsers/clover.js';
import { parseAnyCoverage, parseAnyCoverageContent } from '../src/parsers/index.js';

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
});

describe('Cobertura Parser', () => {
    it('should parse a small Cobertura XML file correctly', async () => {
        const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0" line-rate="0.66667" branch-rate="0.5">
    <packages>
        <package name="src" line-rate="0.66667" branch-rate="0.5">
            <classes>
                <class name="example1.js" filename="src/example1.js" line-rate="0.66667" branch-rate="1.0">
                    <lines>
                        <line number="1" hits="1"/>
                        <line number="2" hits="0"/>
                        <line number="3" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
        
        const result = parseCobertura(xmlContent);
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/example1.js',
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

    it('should handle empty XML correctly', () => {
        const emptyXml = '<?xml version="1.0" encoding="UTF-8"?><coverage></coverage>';
        const result = parseCobertura(emptyXml);
        expect(result.files).toHaveLength(0);
        expect(result.totals).toEqual({
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });
});

describe('Clover Parser', () => {
    it('should parse a small Clover XML file correctly', () => {
        const result = parseCloverFile('test/fixtures/clover.small.xml');
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/example.js',
            lines: { covered: 2, total: 3 },
            branches: { covered: 1, total: 2 },
            functions: { covered: 1, total: 1 },
            coveredLineNumbers: new Set([1, 3, 4]),
            package: 'src'
        });
        expect(result.totals).toEqual({
            lines: { covered: 2, total: 3 },
            branches: { covered: 1, total: 2 },
            functions: { covered: 1, total: 1 }
        });
    });

    it('should parse complex Clover XML with multiple files and packages', () => {
        const result = parseCloverFile('test/fixtures/clover.sample.xml');
        
        expect(result.files).toHaveLength(3);
        
        // Check Calculator.php - using metrics data
        const calculatorFile = result.files.find(f => f.path === 'src/Calculator.php');
        expect(calculatorFile).toBeDefined();
        expect(calculatorFile).toEqual({
            path: 'src/Calculator.php',
            lines: { covered: 6, total: 8 }, // From metrics
            branches: { covered: 1, total: 2 }, // From metrics
            functions: { covered: 2, total: 3 }, // From metrics
            coveredLineNumbers: new Set([4, 5, 9, 10]), // Only stmt lines with count > 0
            package: 'src'
        });
        
        // Check MathUtils.php - using metrics data
        const mathUtilsFile = result.files.find(f => f.path === 'src/MathUtils.php');
        expect(mathUtilsFile).toBeDefined();
        expect(mathUtilsFile).toEqual({
            path: 'src/MathUtils.php',
            lines: { covered: 2, total: 4 }, // From metrics
            branches: { covered: 0, total: 0 }, // From metrics
            functions: { covered: 1, total: 2 }, // From metrics
            coveredLineNumbers: new Set([4]), // Only stmt lines with count > 0
            package: 'src'
        });
        
        // Check CalculatorTest.php - using metrics data
        const testFile = result.files.find(f => f.path === 'tests/CalculatorTest.php');
        expect(testFile).toBeDefined();
        expect(testFile).toEqual({
            path: 'tests/CalculatorTest.php',
            lines: { covered: 6, total: 6 }, // From metrics
            branches: { covered: 1, total: 1 }, // From metrics
            functions: { covered: 3, total: 3 }, // From metrics
            coveredLineNumbers: new Set([9, 10, 14, 15, 19, 20]), // stmt and cond lines with count > 0
            package: 'tests'
        });
        
        // Check totals
        expect(result.totals).toEqual({
            lines: { covered: 14, total: 18 },
            branches: { covered: 2, total: 3 }, // Updated to match actual metrics
            functions: { covered: 6, total: 8 }
        });
    });

    it('should parse Clover XML data string correctly', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover" version="4.4.1">
    <project timestamp="1642781234" name="test">
        <package name="src">
            <file name="test.js" path="src/test.js">
                <line num="1" type="stmt" count="1"/>
                <line num="2" type="stmt" count="0"/>
                <line num="3" type="cond" count="1" truecount="1" falsecount="0"/>
                <line num="4" type="method" count="1"/>
                <metrics statements="2" coveredstatements="1" conditionals="2" coveredconditionals="1" methods="1" coveredmethods="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/test.js',
            lines: { covered: 1, total: 2 },
            branches: { covered: 1, total: 2 },
            functions: { covered: 1, total: 1 },
            coveredLineNumbers: new Set([1, 3]),
            package: 'src'
        });
        expect(result.totals).toEqual({
            lines: { covered: 1, total: 2 },
            branches: { covered: 1, total: 2 },
            functions: { covered: 1, total: 1 }
        });
    });

    it('should handle empty Clover XML correctly', () => {
        const result = parseCloverFile('test/fixtures/clover.empty.xml');
        expect(result.files).toHaveLength(0);
        expect(result.totals).toEqual({
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });

    it('should handle malformed XML with security protection', () => {
        const maliciousXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE coverage [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<coverage generator="clover">
    <project>
        <package name="evil">
            <file name="test.js" path="&xxe;">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        expect(() => parseClover(maliciousXml)).toThrow(/XML content contains potentially dangerous constructs/);
    });

    it('should sanitize file paths to prevent directory traversal', () => {
        const result = parseCloverFile('test/fixtures/clover.malicious.xml');
        
        expect(result.files).toHaveLength(2);
        
        // Check that malicious path is sanitized
        const maliciousFile = result.files.find(f => f.path === 'etc/passwd');
        expect(maliciousFile).toBeDefined();
        expect(maliciousFile?.path).not.toContain('../');
        
        // Check that normal file is preserved
        const normalFile = result.files.find(f => f.path === 'src/normal.js');
        expect(normalFile).toBeDefined();
    });

    it('should handle different line types correctly', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="test">
            <file name="types.js" path="src/types.js">
                <line num="1" type="stmt" count="5"/>
                <line num="2" type="statement" count="0"/>
                <line num="3" type="cond" count="2" truecount="1" falsecount="1"/>
                <line num="4" type="conditional" count="3" truecount="0" falsecount="2"/>
                <line num="5" type="method" count="1"/>
                <line num="6" type="function" count="0"/>
                <line num="7" type="unknown" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(1);
        
        const file = result.files[0];
        expect(file.lines.total).toBe(5); // stmt(2) + cond(2) with count > 0 + unknown(1)
        expect(file.lines.covered).toBe(4); // stmt(1) + cond(2) with count > 0 + unknown(1)
        expect(file.branches.total).toBe(4); // cond(2) + conditional(2)
        expect(file.branches.covered).toBe(3); // cond(1+1) + conditional(0+1)
        expect(file.functions.total).toBe(2); // method + function
        expect(file.functions.covered).toBe(1); // only method with count > 0
        expect(file.coveredLineNumbers).toEqual(new Set([1, 3, 4, 7]));
    });

    it('should handle XML with no project element', () => {
        const invalidXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <package name="test">
        <file name="test.js" path="src/test.js">
            <line num="1" type="stmt" count="1"/>
        </file>
    </package>
</coverage>`;
        
        const result = parseClover(invalidXml);
        expect(result.files).toHaveLength(0);
        expect(result.totals).toEqual({
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });

    it('should handle XML bomb protection', () => {
        // Create a large XML with excessive nesting
        const xmlBomb = '<?xml version="1.0" encoding="UTF-8"?>\n<coverage>' + '<nested>'.repeat(5000) + '</nested>'.repeat(5000) + '</coverage>';
        
        expect(() => parseClover(xmlBomb)).toThrow(/XML content has excessive nesting/);
    });

    it('should prioritize metrics over line parsing when available', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="test">
            <file name="metrics-test.js" path="src/metrics-test.js">
                <line num="1" type="stmt" count="1"/>
                <line num="2" type="stmt" count="0"/>
                <metrics statements="10" coveredstatements="7" conditionals="4" coveredconditionals="3" methods="2" coveredmethods="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(1);
        
        const file = result.files[0];
        // Should use metrics data instead of line parsing
        expect(file.lines).toEqual({ covered: 7, total: 10 });
        expect(file.branches).toEqual({ covered: 3, total: 4 });
        expect(file.functions).toEqual({ covered: 1, total: 2 });
    });
});

describe('Auto-detection', () => {
    it('should auto-detect LCOV files', async () => {
        const result = await parseAnyCoverage('test/fixtures/lcov.small.info');
        expect(result.files).toHaveLength(1);
        expect(result.files[0].path).toBe('sample/file/path');
    });

    it('should auto-detect Clover XML files', async () => {
        const result = await parseAnyCoverage('test/fixtures/clover.small.xml');
        expect(result.files).toHaveLength(1);
        expect(result.files[0].path).toBe('src/example.js');
        expect(result.files[0].package).toBe('src');
    });

    it('should auto-detect Cobertura XML files', async () => {
        const result = await parseAnyCoverage('test/fixtures/cobertura.small.xml');
        expect(result.files).toHaveLength(2);
    });

    it('should auto-detect content format with hints', () => {
        const cloverContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="test">
            <file name="test.js" path="src/test.js">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseAnyCoverageContent(cloverContent, 'clover');
        expect(result.files).toHaveLength(1);
        expect(result.files[0].path).toBe('src/test.js');
    });

    it('should auto-detect Clover from content without hint', () => {
        const cloverContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="test">
            <file name="test.js" path="src/test.js">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseAnyCoverageContent(cloverContent);
        expect(result.files).toHaveLength(1);
        expect(result.files[0].path).toBe('src/test.js');
    });
});