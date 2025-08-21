import { describe, it, expect } from 'vitest';
import { parseClover, parseCloverFile } from '../../src/parsers/clover.js';

describe('Clover Parser - Core Functionality', () => {
    it('should parse a small Clover XML file correctly', async () => {
        const result = await parseCloverFile('test/fixtures/clover/clover.small.xml');
        
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

    it('should parse complex Clover XML with multiple files and packages', async () => {
        const result = await parseCloverFile('test/fixtures/clover/clover.sample.xml');
        
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

    it('should handle empty Clover XML correctly', async () => {
        const result = await parseCloverFile('test/fixtures/clover/clover.empty.xml');
        expect(result.files).toHaveLength(0);
        expect(result.totals).toEqual({
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
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

    it('should handle deeply nested package structures', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <packages>
            <package name="com.example.deep.nested.package">
                <file name="DeepFile.java" path="com/example/deep/nested/package/DeepFile.java">
                    <line num="1" type="stmt" count="1"/>
                </file>
            </package>
        </packages>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(1);
        
        const file = result.files[0];
        expect(file.path).toBe('com/example/deep/nested/package/DeepFile.java');
        expect(file.package).toBe('com.example.deep.nested.package');
    });

    it('should handle mixed single and array structures', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="single">
            <file name="single.js" path="src/single.js">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
        <package name="multiple">
            <file name="multi1.js" path="src/multi1.js">
                <line num="1" type="stmt" count="1"/>
            </file>
            <file name="multi2.js" path="src/multi2.js">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(3);
        
        const singleFile = result.files.find(f => f.path === 'src/single.js');
        expect(singleFile?.package).toBe('single');
        
        const multi1File = result.files.find(f => f.path === 'src/multi1.js');
        expect(multi1File?.package).toBe('multiple');
        
        const multi2File = result.files.find(f => f.path === 'src/multi2.js');
        expect(multi2File?.package).toBe('multiple');
    });
});
