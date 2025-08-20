import { describe, it, expect } from 'vitest';
import { parseClover } from '../src/parsers/clover.js';

describe('Clover Parser - Edge Cases & Performance', () => {
    it('should handle very large line numbers safely', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="test">
            <file name="large.js" path="src/large.js">
                <line num="999999" type="stmt" count="1"/>
                <line num="1000000" type="stmt" count="0"/>
                <line num="2147483647" type="cond" count="1" truecount="1" falsecount="0"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(1);
        
        const file = result.files[0];
        expect(file.lines.total).toBe(3);
        expect(file.lines.covered).toBe(2);
        expect(file.coveredLineNumbers).toEqual(new Set([999999, 2147483647]));
    });

    it('should handle malformed line numbers gracefully', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="test">
            <file name="malformed.js" path="src/malformed.js">
                <line num="abc" type="stmt" count="1"/>
                <line num="1.5" type="stmt" count="1"/>
                <line num="" type="stmt" count="1"/>
                <line num="5" type="stmt" count="xyz"/>
                <line num="6" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(1);
        
        const file = result.files[0];
        // Line num="1.5" parses to 1 (parseInt truncates), line num="6" is valid
        // Line num="5" with count="xyz" is invalid (count is null)
        expect(file.lines.total).toBe(2);
        expect(file.lines.covered).toBe(2);
        expect(file.coveredLineNumbers).toEqual(new Set([1, 6]));
    });

    it('should handle files with no lines', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="empty">
            <file name="empty.js" path="src/empty.js">
                <metrics statements="0" coveredstatements="0" conditionals="0" coveredconditionals="0" methods="0" coveredmethods="0"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(1);
        
        const file = result.files[0];
        expect(file.lines).toEqual({ covered: 0, total: 0 });
        expect(file.branches).toEqual({ covered: 0, total: 0 });
        expect(file.functions).toEqual({ covered: 0, total: 0 });
        expect(file.coveredLineNumbers.size).toBe(0);
    });

    it('should handle negative counts safely', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="negative">
            <file name="negative.js" path="src/negative.js">
                <line num="1" type="stmt" count="-1"/>
                <line num="2" type="cond" count="-5" truecount="-1" falsecount="-2"/>
                <line num="3" type="method" count="-10"/>
                <metrics statements="-1" coveredstatements="-2" methods="-3" coveredmethods="-4"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(1);
        
        const file = result.files[0];
        // Should use metrics and handle negative values appropriately
        expect(file.lines.total).toBe(-1);
        expect(file.lines.covered).toBe(-2);
        expect(file.functions.total).toBe(-3);
        expect(file.functions.covered).toBe(-4);
        // Covered line numbers should still be empty (negative counts don't add lines)
        expect(file.coveredLineNumbers.size).toBe(0);
    });

    it('should handle missing required attributes gracefully', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="missing">
            <file path="src/missing.js">
                <line type="stmt" count="1"/>
                <line num="2" count="1"/>
                <line num="3" type="stmt"/>
            </file>
            <file name="valid.js" path="src/valid.js">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        // The first file has @_path so it should be processed, but empty files might be filtered out
        expect(result.files).toHaveLength(1);
        
        // Only the valid file should be processed
        const validFile = result.files.find(f => f.path === 'src/valid.js');
        expect(validFile).toBeDefined();
        expect(validFile?.lines.total).toBe(1);
        expect(validFile?.lines.covered).toBe(1);
    });

    it('should handle files with missing both path and name attributes', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="missing">
            <file>
                <line num="1" type="stmt" count="1"/>
            </file>
            <file name="valid.js" path="src/valid.js">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        // Files without both @_path and @_name are skipped
        expect(result.files).toHaveLength(1);
        
        // Only the valid file should be processed
        const validFile = result.files.find(f => f.path === 'src/valid.js');
        expect(validFile).toBeDefined();
        expect(validFile?.lines.total).toBe(1);
        expect(validFile?.lines.covered).toBe(1);
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

    it('should handle Unicode and special characters in paths', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="unicode-测试">
            <file name="测试.js" path="src/测试文件.js">
                <line num="1" type="stmt" count="1"/>
            </file>
            <file name="special chars.js" path="src/special chars & symbols!@#$.js">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(2);
        
        const unicodeFile = result.files.find(f => f.path === 'src/测试文件.js');
        expect(unicodeFile).toBeDefined();
        expect(unicodeFile?.package).toBe('unicode-测试');
        
        const specialFile = result.files.find(f => f.path === 'src/special chars & symbols!@#$.js');
        expect(specialFile).toBeDefined();
    });

    it('should handle extremely large metrics values', () => {
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="large">
            <file name="large.js" path="src/large.js">
                <metrics 
                    statements="2147483647" 
                    coveredstatements="1073741824" 
                    conditionals="999999999" 
                    coveredconditionals="500000000"
                    methods="1000000"
                    coveredmethods="750000"
                />
            </file>
        </package>
    </project>
</coverage>`;
        
        const result = parseClover(cloverXml);
        expect(result.files).toHaveLength(1);
        
        const file = result.files[0];
        expect(file.lines.total).toBe(2147483647);
        expect(file.lines.covered).toBe(1073741824);
        expect(file.branches.total).toBe(999999999);
        expect(file.branches.covered).toBe(500000000);
        expect(file.functions.total).toBe(1000000);
        expect(file.functions.covered).toBe(750000);
    });

    it('should handle performance with many files', () => {
        // Generate XML with 100 files
        const files = Array.from({ length: 100 }, (_, i) => `
            <file name="file${i}.js" path="src/file${i}.js">
                <line num="1" type="stmt" count="${i % 2}"/>
                <line num="2" type="stmt" count="${(i + 1) % 2}"/>
                <line num="3" type="cond" count="1" truecount="1" falsecount="0"/>
                <metrics statements="2" coveredstatements="1" conditionals="2" coveredconditionals="1" methods="1" coveredmethods="1"/>
            </file>
        `).join('');
        
        const cloverXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover">
    <project>
        <package name="performance">
            ${files}
        </package>
    </project>
</coverage>`;
        
        const start = Date.now();
        const result = parseClover(cloverXml);
        const duration = Date.now() - start;
        
        expect(result.files).toHaveLength(100);
        expect(duration).toBeLessThan(1000); // Should parse 100 files in under 1 second
        
        // Verify totals are computed correctly
        expect(result.totals.lines.total).toBe(200); // 2 statements per file * 100 files
        expect(result.totals.lines.covered).toBe(100); // 1 covered statement per file * 100 files
        expect(result.totals.functions.total).toBe(100); // 1 method per file * 100 files
        expect(result.totals.functions.covered).toBe(100); // 1 covered method per file * 100 files
    });
});
