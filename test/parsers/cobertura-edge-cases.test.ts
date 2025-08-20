import { describe, it, expect } from 'vitest';
import { parseCobertura, parseCoberturaFile } from '../../src/parsers/cobertura.js';

describe('Cobertura Parser - Edge Cases & Robustness', () => {
    describe('Security & Malformed Input', () => {
        it('should handle malformed XML with security protection', () => {
            const maliciousXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE coverage [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<coverage version="1.0" line-rate="0.8" branch-rate="0.7">
    <packages>
        <package name="evil">
            <classes>
                <class name="Test" filename="&xxe;">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            expect(() => parseCobertura(maliciousXml)).toThrow(/Cobertura XML security validation failed/);
        });

        it('should sanitize file paths to prevent directory traversal', () => {
            const result = parseCoberturaFile('test/fixtures/cobertura.malicious.xml');
            
            expect(result.files).toHaveLength(2);
            
            // Check that malicious path is sanitized
            const maliciousFile = result.files.find((f) => f.path === 'etc/passwd');
            expect(maliciousFile).toBeDefined();
            expect(maliciousFile?.path).not.toContain('../');
            
            // Check that normal file is preserved
            const normalFile = result.files.find((f) => f.path === 'src/normal.js');
            expect(normalFile).toBeDefined();
        });

        it('should handle XML bomb protection', () => {
            // Create a large XML with excessive nesting
            const xmlBomb = '<?xml version="1.0" encoding="UTF-8"?>\n<coverage>' + '<nested>'.repeat(5000) + '</nested>'.repeat(5000) + '</coverage>';
            
            expect(() => parseCobertura(xmlBomb)).toThrow(/Cobertura XML file too complex/);
        });
    });

    describe('Data Validation & Edge Cases', () => {
        it('should handle very large line numbers safely', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0" line-rate="0.8" branch-rate="0.7">
    <packages>
        <package name="large">
            <classes>
                <class name="LargeFile" filename="src/large.js">
                    <lines>
                        <line number="999999" hits="1"/>
                        <line number="1000000" hits="0"/>
                        <line number="2147483647" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.lines.total).toBe(3);
            expect(file.lines.covered).toBe(2);
            expect(file.coveredLineNumbers).toEqual(new Set([999999, 2147483647]));
        });

        it('should handle malformed line numbers gracefully', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="malformed">
            <classes>
                <class name="Test" filename="src/malformed.js">
                    <lines>
                        <line number="abc" hits="1"/>
                        <line number="1.5" hits="1"/>
                        <line number="" hits="1"/>
                        <line number="5" hits="xyz"/>
                        <line number="6" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            // Line number="1.5" parses to 1 (parseInt truncates), line number="6" is valid
            // Line number="5" with hits="xyz" is invalid (hits is null)
            expect(file.lines.total).toBe(2);
            expect(file.lines.covered).toBe(2);
            expect(file.coveredLineNumbers).toEqual(new Set([1, 6]));
        });

        it('should handle files with no lines', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="empty">
            <classes>
                <class name="Empty" filename="src/empty.js">
                    <methods>
                    </methods>
                    <lines>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.lines).toEqual({ covered: 0, total: 0 });
            expect(file.branches).toEqual({ covered: 0, total: 0 });
            expect(file.functions).toEqual({ covered: 0, total: 0 });
            expect(file.coveredLineNumbers.size).toBe(0);
        });

        it('should handle negative hits safely', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="negative">
            <classes>
                <class name="Negative" filename="src/negative.js">
                    <lines>
                        <line number="1" hits="-1"/>
                        <line number="2" hits="-5"/>
                        <line number="3" hits="0"/>
                        <line number="4" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.lines.total).toBe(4);
            // Only positive hits count as covered
            expect(file.lines.covered).toBe(1);
            expect(file.coveredLineNumbers).toEqual(new Set([4]));
        });

        it('should handle extremely large hit counts', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="extreme">
            <classes>
                <class name="Extreme" filename="src/extreme.js">
                    <lines>
                        <line number="1" hits="999999999"/>
                        <line number="2" hits="2147483647"/>
                        <line number="3" hits="0"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.lines.total).toBe(3);
            expect(file.lines.covered).toBe(2);
            expect(file.coveredLineNumbers).toEqual(new Set([1, 2]));
        });

        it('should handle Unicode file paths', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="unicode">
            <classes>
                <class name="Unicode" filename="src/测试/файл.js">
                    <lines>
                        <line number="1" hits="1"/>
                        <line number="2" hits="0"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.path).toBe('src/测试/файл.js');
            expect(file.lines.total).toBe(2);
            expect(file.lines.covered).toBe(1);
        });

        it('should handle missing attributes gracefully', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage>
    <packages>
        <package>
            <classes>
                <class filename="src/missing.js">
                    <methods>
                        <method>
                            <lines>
                                <line hits="1"/>
                            </lines>
                        </method>
                    </methods>
                    <lines>
                        <line number="1"/>
                        <line hits="2"/>
                        <line number="3" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            // Only the line with both number and hits should be counted
            expect(file.lines.total).toBe(1);
            expect(file.lines.covered).toBe(1);
            expect(file.functions.total).toBe(0); // Method without name not counted
            expect(file.functions.covered).toBe(0);
        });
    });

    describe('Complex Branch Coverage', () => {
        it('should handle complex branch coverage scenarios', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="branches">
            <classes>
                <class name="BranchTest" filename="src/branches.js">
                    <lines>
                        <line number="1" hits="10" branch="true" condition-coverage="100% (4/4)"/>
                        <line number="2" hits="5" branch="true" condition-coverage="50% (1/2)"/>
                        <line number="3" hits="0" branch="true" condition-coverage="0% (0/6)"/>
                        <line number="4" hits="8" branch="true" condition-coverage="33% (1/3)"/>
                        <line number="5" hits="2" branch="false"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.lines.total).toBe(5);
            expect(file.lines.covered).toBe(4); // All except line 3
            expect(file.branches.total).toBe(15); // 4+2+6+3
            expect(file.branches.covered).toBe(6); // 4+1+0+1
        });

        it('should handle malformed condition-coverage gracefully', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="malformed">
            <classes>
                <class name="BadBranches" filename="src/bad.js">
                    <lines>
                        <line number="1" hits="1" condition-coverage="invalid"/>
                        <line number="2" hits="1" condition-coverage="50%"/>
                        <line number="3" hits="1" condition-coverage="(2/4)"/>
                        <line number="4" hits="1" condition-coverage="75% (abc/def)"/>
                        <line number="5" hits="1" condition-coverage="100% (2/2)"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.lines.total).toBe(5);
            expect(file.lines.covered).toBe(5);
            // Only the last line has valid branch coverage format
            expect(file.branches.total).toBe(2);
            expect(file.branches.covered).toBe(2);
        });
    });

    describe('Method Coverage Edge Cases', () => {
        it('should handle methods without lines', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="methods">
            <classes>
                <class name="MethodTest" filename="src/methods.js">
                    <methods>
                        <method name="empty1" signature="()V"/>
                        <method name="empty2" signature="()V">
                            <lines>
                            </lines>
                        </method>
                        <method name="withLines" signature="()V">
                            <lines>
                                <line number="5" hits="1"/>
                            </lines>
                        </method>
                    </methods>
                    <lines>
                        <line number="5" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.functions.total).toBe(3);
            expect(file.functions.covered).toBe(1); // Only method with covered lines
        });

        it('should handle nested method structures', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="nested">
            <classes>
                <class name="Nested" filename="src/nested.js">
                    <methods>
                        <method name="outer" signature="()V">
                            <lines>
                                <line number="1" hits="2"/>
                                <line number="2" hits="0"/>
                            </lines>
                        </method>
                        <method name="inner" signature="()V">
                            <lines>
                                <line number="5" hits="3"/>
                            </lines>
                        </method>
                    </methods>
                    <lines>
                        <line number="1" hits="2"/>
                        <line number="2" hits="0"/>
                        <line number="5" hits="3"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.functions.total).toBe(2);
            expect(file.functions.covered).toBe(2); // Both methods have some covered lines
            expect(file.lines.total).toBe(3);
            expect(file.lines.covered).toBe(2);
        });
    });

    describe('Alternative XML Structures', () => {
        it('should handle packages without names', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package line-rate="0.8">
            <classes>
                <class name="Anonymous" filename="src/anonymous.js">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.path).toBe('src/anonymous.js');
            expect(file.package).toBeUndefined();
        });

        it('should handle classes without filenames', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="com.example">
            <classes>
                <class name="NoFilename">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
                <class name="WithDots.Inner">
                    <lines>
                        <line number="2" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(2);
            
            // Should generate filename from package + class name
            const file1 = result.files.find(f => f.path === 'com/example/NoFilename.js');
            expect(file1).toBeDefined();
            
            const file2 = result.files.find(f => f.path === 'com/example/WithDots/Inner.js');
            expect(file2).toBeDefined();
        });

        it('should handle single package structure', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="single">
            <classes>
                <class name="Single" filename="src/single.js">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('src/single.js');
        });
    });

    describe('Empty/Null Handling', () => {
        it('should handle completely empty coverage', () => {
            const result = parseCoberturaFile('test/fixtures/cobertura.empty.xml');
            expect(result.files).toHaveLength(0);
            expect(result.totals).toEqual({
                lines: { covered: 0, total: 0 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 0, total: 0 }
            });
        });

        it('should handle null/undefined elements gracefully', () => {
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="null-test">
            <classes>
                <class name="NullTest" filename="src/null.js">
                    <methods>
                        <method/>
                        <method name="valid">
                            <lines>
                                <line number="1" hits="1"/>
                            </lines>
                        </method>
                    </methods>
                    <lines>
                        <line/>
                        <line number="1" hits="1"/>
                        <line number="2"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseCobertura(coberturaXml);
            expect(result.files).toHaveLength(1);
            
            const file = result.files[0];
            expect(file.functions.total).toBe(1); // Only named method
            expect(file.functions.covered).toBe(1);
            expect(file.lines.total).toBe(1); // Only valid line
            expect(file.lines.covered).toBe(1);
        });
    });

    describe('Performance & Scalability', () => {
        it('should handle large number of files efficiently', () => {
            // Generate XML with many files
            const packagesXml = Array.from({ length: 50 }, (_, i) => `
                <package name="pkg${i}">
                    <classes>
                        <class name="Class${i}" filename="src/class${i}.js">
                            <lines>
                                <line number="1" hits="${i % 3}"/>
                                <line number="2" hits="${(i + 1) % 3}"/>
                            </lines>
                        </class>
                    </classes>
                </package>
            `).join('');
            
            const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        ${packagesXml}
    </packages>
</coverage>`;
            
            const start = Date.now();
            const result = parseCobertura(coberturaXml);
            const duration = Date.now() - start;
            
            expect(result.files).toHaveLength(50);
            expect(duration).toBeLessThan(1000); // Should complete within 1 second
            
            // Verify totals are computed correctly
            const expectedTotal = 50 * 2; // 50 files × 2 lines each
            expect(result.totals.lines.total).toBe(expectedTotal);
        });
    });

    describe('Error Handling & Recovery', () => {
        it('should provide clear error messages for different failure modes', () => {
            const invalidXml = '<?xml version="1.0"?><invalid><broken';
            
            expect(() => parseCobertura(invalidXml)).toThrow();
        });

        it('should handle missing coverage root gracefully', () => {
            const noRootXml = '<?xml version="1.0"?><root><other>content</other></root>';
            
            const result = parseCobertura(noRootXml);
            expect(result.files).toHaveLength(0);
            expect(result.totals).toEqual({
                lines: { covered: 0, total: 0 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 0, total: 0 }
            });
        });

        it('should handle file read errors gracefully', () => {
            expect(() => parseCoberturaFile('nonexistent.xml')).toThrow(/Failed to read Cobertura file/);
        });
    });
});
