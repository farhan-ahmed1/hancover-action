import { describe, it, expect } from 'vitest';
import { parseJaCoCo, parseJaCoCoFile } from '../../src/parsers/jacoco.js';

describe('JaCoCo Parser - Edge Cases & Robustness', () => {
    describe('Security & Malformed Input', () => {
        it('should handle malformed XML with security protection', () => {
            const maliciousXml = `<?xml version="1.0"?>
            <!DOCTYPE report [
                <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <report>
                <value>&xxe;</value>
            </report>`;
            
            expect(() => parseJaCoCo(maliciousXml)).toThrow(/security validation failed/);
        });

        it('should sanitize file paths to prevent directory traversal', async () => {
            const result = await parseJaCoCoFile('test/fixtures/jacoco/jacoco.edge-cases.xml');
            
            // Find the file that had directory traversal attempt
            const maliciousFile = result.files.find(f => f.path.includes('passwd'));
            expect(maliciousFile).toBeDefined();
            
            // Check that the path has been sanitized (no .. or leading slashes)
            expect(maliciousFile!.path).not.toContain('..');
            expect(maliciousFile!.path).not.toMatch(/^\/+/);
            expect(maliciousFile!.path).toBe('etc/passwd/etc/passwd.java'); // This is how the parser constructs it
        });

        it('should handle XML bomb protection', () => {
            const xmlBomb = `<?xml version="1.0"?>
            <report>${'<element>'.repeat(5000)}content${'</element>'.repeat(5000)}</report>`;
            
            expect(() => parseJaCoCo(xmlBomb)).toThrow(/excessive nesting/);
        });
    });

    describe('Data Validation & Edge Cases', () => {
        it('should handle very large line numbers safely', async () => {
            const result = await parseJaCoCoFile('test/fixtures/jacoco/jacoco.edge-cases.xml');
            
            // Find the file with large numbers
            const bigDataFile = result.files.find(f => f.path.includes('BigData'));
            expect(bigDataFile).toBeDefined();
            
            // Check that large numbers are handled correctly
            expect(bigDataFile!.coveredLineNumbers.has(999999999)).toBe(true);
            expect(bigDataFile!.lines.covered).toBe(1); // Line-level parsing shows 1 covered line
            expect(bigDataFile!.lines.total).toBe(1); // Line-level parsing shows 1 total line
        });

        it('should handle malformed line numbers gracefully', async () => {
            const result = await parseJaCoCoFile('test/fixtures/jacoco/jacoco.malformed.xml');
            
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('com/example/BadClass.java');
            
            // Should ignore invalid line numbers and continue processing
            expect(result.files[0].lines.total).toBe(1); // Only line 5.5 converted to 5
            expect(result.files[0].lines.covered).toBe(1);
            expect(result.files[0].coveredLineNumbers.has(5)).toBe(true);
        });

        it('should handle files with no lines', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
            <report name="test">
                <package name="com/test">
                    <class name="com/test/EmptyClass" sourcefilename="EmptyClass.java">
                        <counter type="CLASS" missed="0" covered="1"/>
                    </class>
                    <sourcefile name="EmptyClass.java">
                        <!-- No lines -->
                        <counter type="CLASS" missed="0" covered="1"/>
                    </sourcefile>
                </package>
            </report>`;
            
            const result = parseJaCoCo(xmlData);
            
            expect(result.files).toHaveLength(1);
            expect(result.files[0]).toEqual({
                path: 'com/test/EmptyClass.java',
                lines: { covered: 0, total: 0 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 0, total: 0 },
                coveredLineNumbers: new Set(),
                package: 'com/test'
            });
        });

        it('should handle negative hits safely', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
            <report name="test">
                <package name="com/test">
                    <sourcefile name="Negative.java">
                        <line nr="1" mi="-5" ci="2" mb="-1" cb="1"/>
                        <line nr="2" mi="0" ci="-3" mb="0" cb="-2"/>
                        <counter type="LINE" missed="-2" covered="3"/>
                    </sourcefile>
                </package>
            </report>`;
            
            const result = parseJaCoCo(xmlData);
            
            expect(result.files).toHaveLength(1);
            expect(result.files[0].lines.covered).toBe(1); // Only line 1 has positive covered instructions
            expect(result.files[0].lines.total).toBe(1); // Line 2 has negative covered instructions, so excluded
            expect(result.files[0].branches.covered).toBe(1); // Only positive branch coverage counted
            expect(result.files[0].branches.total).toBe(1); // Only positive total branches counted
        });

        it('should handle extremely large hit counts', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
            <report name="test">
                <package name="com/test">
                    <sourcefile name="Huge.java">
                        <line nr="1" mi="2147483647" ci="2147483647" mb="1000000" cb="1000000"/>
                        <counter type="LINE" missed="2147483647" covered="2147483647"/>
                        <counter type="BRANCH" missed="1000000" covered="1000000"/>
                    </sourcefile>
                </package>
            </report>`;
            
            const result = parseJaCoCo(xmlData);
            
            expect(result.files).toHaveLength(1);
            expect(result.files[0].lines.covered).toBe(1);
            expect(result.files[0].lines.total).toBe(1);
            expect(result.files[0].branches.covered).toBe(1000000);
            expect(result.files[0].branches.total).toBe(2000000);
        });

        it('should handle Unicode file paths', async () => {
            const result = await parseJaCoCoFile('test/fixtures/jacoco/jacoco.edge-cases.xml');
            
            // Find the Unicode test file
            const unicodeFile = result.files.find(f => f.path.includes('CalculatorTest'));
            expect(unicodeFile).toBeDefined();
            expect(unicodeFile!.path).toBe('com/example/测试/CalculatorTest.java');
            expect(unicodeFile!.package).toBe('com/example/测试');
        });

        it('should handle missing required attributes gracefully', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
            <report name="test">
                <package name="com/test">
                    <class sourcefilename="NoName.java">
                        <method desc="()V" line="5">
                            <counter type="METHOD" missed="0" covered="1"/>
                        </method>
                    </class>
                    <sourcefile name="NoName.java">
                        <line mi="0" ci="1"/>
                        <line nr="5" ci="1"/>
                    </sourcefile>
                </package>
            </report>`;
            
            const result = parseJaCoCo(xmlData);
            
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('com/test/NoName.java');
            expect(result.files[0].lines.covered).toBe(1); // Only line 5 has nr attribute
            expect(result.files[0].lines.total).toBe(1);
            expect(result.files[0].functions.total).toBe(0); // Method without name is ignored
        });

        it('should handle mixed single and array structures', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
            <report name="test">
                <package name="com/test">
                    <class name="com/test/Single" sourcefilename="Single.java">
                        <method name="singleMethod" desc="()V" line="5">
                            <counter type="METHOD" missed="0" covered="1"/>
                        </method>
                    </class>
                    <sourcefile name="Single.java">
                        <line nr="5" mi="0" ci="1" mb="0" cb="0"/>
                    </sourcefile>
                </package>
                <package name="com/test2">
                    <class name="com/test2/Multi1" sourcefilename="Multi.java">
                        <method name="method1" desc="()V" line="5">
                            <counter type="METHOD" missed="0" covered="1"/>
                        </method>
                    </class>
                    <class name="com/test2/Multi2" sourcefilename="Multi.java">
                        <method name="method2" desc="()V" line="10">
                            <counter type="METHOD" missed="1" covered="0"/>
                        </method>
                    </class>
                    <sourcefile name="Multi.java">
                        <line nr="5" mi="0" ci="1" mb="0" cb="0"/>
                        <line nr="10" mi="1" ci="0" mb="0" cb="0"/>
                    </sourcefile>
                </package>
            </report>`;
            
            const result = parseJaCoCo(xmlData);
            
            expect(result.files).toHaveLength(2);
            
            const singleFile = result.files.find(f => f.path === 'com/test/Single.java');
            expect(singleFile).toBeDefined();
            expect(singleFile!.functions.total).toBeGreaterThan(0); // Should have methods from class data
            
            const multiFile = result.files.find(f => f.path === 'com/test2/Multi.java');
            expect(multiFile).toBeDefined();
            expect(multiFile!.functions.total).toBeGreaterThan(0); // Should have methods from class data
        });

        it('should handle XML with no report element', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
            <notareport>
                <package name="com/test">
                    <sourcefile name="Test.java">
                        <line nr="1" mi="0" ci="1"/>
                    </sourcefile>
                </package>
            </notareport>`;
            
            const result = parseJaCoCo(xmlData);
            
            expect(result.files).toHaveLength(0);
            expect(result.totals).toEqual({
                lines: { covered: 0, total: 0 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 0, total: 0 }
            });
        });

        it('should handle invalid counter types gracefully', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
            <report name="test">
                <package name="com/test">
                    <sourcefile name="InvalidCounters.java">
                        <line nr="1" mi="0" ci="1" mb="0" cb="0"/>
                        <counter type="UNKNOWN" missed="5" covered="10"/>
                        <counter type="LINE" missed="invalid" covered="text"/>
                        <counter type="" missed="1" covered="1"/>
                        <counter missed="1" covered="1"/>
                    </sourcefile>
                </package>
            </report>`;
            
            const result = parseJaCoCo(xmlData);
            
            expect(result.files).toHaveLength(1);
            expect(result.files[0].lines).toEqual({ covered: 1, total: 1 }); // From line data
            expect(result.files[0].branches).toEqual({ covered: 0, total: 0 });
            expect(result.files[0].functions).toEqual({ covered: 0, total: 0 });
        });
    });
    
    describe('Error Handling', () => {
        it('should provide descriptive error messages for parsing failures', () => {
            const invalidXml = '<not-valid-xml';
            
            expect(() => parseJaCoCo(invalidXml)).toThrow(/Failed to parse JaCoCo XML/);
        });

        it('should handle file read errors gracefully', async () => {
            await expect(parseJaCoCoFile('/nonexistent/file.xml')).rejects.toThrow(/Failed to read JaCoCo file/);
        });

        it('should handle completely empty XML', () => {
            const emptyXml = '';
            
            const result = parseJaCoCo(emptyXml);
            expect(result.files).toHaveLength(0);
            expect(result.totals).toEqual({
                lines: { covered: 0, total: 0 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 0, total: 0 }
            });
        });

        it('should handle XML with only declaration', () => {
            const xmlData = '<?xml version="1.0" encoding="UTF-8"?>';
            
            const result = parseJaCoCo(xmlData);
            expect(result.files).toHaveLength(0);
            expect(result.totals).toEqual({
                lines: { covered: 0, total: 0 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 0, total: 0 }
            });
        });
    });

    describe('Integration with Mixed Data Sources', () => {
        it('should correctly merge data from classes and sourcefiles', () => {
            const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
            <report name="test">
                <package name="com/test">
                    <class name="com/test/Mixed" sourcefilename="Mixed.java">
                        <method name="method1" desc="()V" line="5">
                            <counter type="METHOD" missed="0" covered="1"/>
                        </method>
                        <method name="method2" desc="()V" line="10">
                            <counter type="METHOD" missed="1" covered="0"/>
                        </method>
                        <counter type="METHOD" missed="1" covered="1"/>
                    </class>
                    <sourcefile name="Mixed.java">
                        <line nr="5" mi="0" ci="2" mb="0" cb="1"/>
                        <line nr="10" mi="1" ci="0" mb="1" cb="0"/>
                        <line nr="15" mi="0" ci="1" mb="0" cb="0"/>
                        <counter type="LINE" missed="1" covered="2"/>
                        <counter type="BRANCH" missed="1" covered="1"/>
                    </sourcefile>
                </package>
            </report>`;
            
            const result = parseJaCoCo(xmlData);
            
            expect(result.files).toHaveLength(1);
            expect(result.files[0]).toEqual({
                path: 'com/test/Mixed.java',
                lines: { covered: 2, total: 3 }, // From sourcefile line data
                branches: { covered: 1, total: 2 }, // From sourcefile line data
                functions: { covered: 1, total: 2 }, // From class method data
                coveredLineNumbers: new Set([5, 15]), // From sourcefile line data
                package: 'com/test'
            });
        });
    });
});
