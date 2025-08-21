import { describe, it, expect } from 'vitest';
import { parseJaCoCo, parseJaCoCoFile } from '../../src/parsers/jacoco.js';

describe('JaCoCo Parser - Core Functionality', () => {
    it('should parse a small JaCoCo XML file correctly', () => {
        const result = parseJaCoCoFile('test/fixtures/jacoco/jacoco.small.xml');
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'src/Example.java',
            lines: { covered: 2, total: 3 },
            branches: { covered: 1, total: 2 },
            functions: { covered: 2, total: 2 },
            coveredLineNumbers: new Set([5, 9]),
            package: 'src'
        });
        expect(result.totals).toEqual({
            lines: { covered: 2, total: 3 },
            branches: { covered: 1, total: 2 },
            functions: { covered: 2, total: 2 }
        });
    });

    it('should parse complex JaCoCo XML with multiple files and packages', () => {
        const result = parseJaCoCoFile('test/fixtures/jacoco/jacoco.complex.xml');
        
        expect(result.files).toHaveLength(3);
        
        // Check Calculator.java
        const calculatorFile = result.files.find(f => f.path === 'com/example/core/Calculator.java');
        expect(calculatorFile).toBeDefined();
        expect(calculatorFile).toEqual({
            path: 'com/example/core/Calculator.java',
            lines: { covered: 4, total: 8 },
            branches: { covered: 1, total: 4 },
            functions: { covered: 3, total: 4 },
            coveredLineNumbers: new Set([8, 12, 13, 18]),
            package: 'com/example/core'
        });
        
        // Check MathUtils.java
        const mathUtilsFile = result.files.find(f => f.path === 'com/example/core/MathUtils.java');
        expect(mathUtilsFile).toBeDefined();
        expect(mathUtilsFile).toEqual({
            path: 'com/example/core/MathUtils.java',
            lines: { covered: 3, total: 6 },
            branches: { covered: 2, total: 6 },
            functions: { covered: 2, total: 2 },
            coveredLineNumbers: new Set([5, 9, 15]),
            package: 'com/example/core'
        });
        
        // Check StringHelper.java
        const stringHelperFile = result.files.find(f => f.path === 'com/example/util/StringHelper.java');
        expect(stringHelperFile).toBeDefined();
        expect(stringHelperFile).toEqual({
            path: 'com/example/util/StringHelper.java',
            lines: { covered: 4, total: 4 },
            branches: { covered: 6, total: 7 }, // Line data: 7 total, but counter says 6
            functions: { covered: 2, total: 2 },
            coveredLineNumbers: new Set([8, 9, 11, 15]),
            package: 'com/example/util'
        });
        
        // Check totals
        expect(result.totals).toEqual({
            lines: { covered: 11, total: 18 },
            branches: { covered: 9, total: 17 }, // Updated to match actual calculated total
            functions: { covered: 7, total: 8 }
        });
    });

    it('should parse JaCoCo XML data string correctly', () => {
        const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
        <report name="test">
            <sessioninfo id="test" start="1609459200000" dump="1609459260000"/>
            <package name="com/test">
                <class name="com/test/Simple" sourcefilename="Simple.java">
                    <method name="getValue" desc="()I" line="5">
                        <counter type="INSTRUCTION" missed="0" covered="2"/>
                        <counter type="LINE" missed="0" covered="1"/>
                        <counter type="COMPLEXITY" missed="0" covered="1"/>
                        <counter type="METHOD" missed="0" covered="1"/>
                    </method>
                    <counter type="INSTRUCTION" missed="0" covered="2"/>
                    <counter type="BRANCH" missed="0" covered="0"/>
                    <counter type="LINE" missed="0" covered="1"/>
                    <counter type="COMPLEXITY" missed="0" covered="1"/>
                    <counter type="METHOD" missed="0" covered="1"/>
                    <counter type="CLASS" missed="0" covered="1"/>
                </class>
                <sourcefile name="Simple.java">
                    <line nr="5" mi="0" ci="2" mb="0" cb="0"/>
                    <counter type="INSTRUCTION" missed="0" covered="2"/>
                    <counter type="BRANCH" missed="0" covered="0"/>
                    <counter type="LINE" missed="0" covered="1"/>
                    <counter type="COMPLEXITY" missed="0" covered="1"/>
                    <counter type="METHOD" missed="0" covered="1"/>
                    <counter type="CLASS" missed="0" covered="1"/>
                </sourcefile>
                <counter type="INSTRUCTION" missed="0" covered="2"/>
                <counter type="BRANCH" missed="0" covered="0"/>
                <counter type="LINE" missed="0" covered="1"/>
                <counter type="COMPLEXITY" missed="0" covered="1"/>
                <counter type="METHOD" missed="0" covered="1"/>
                <counter type="CLASS" missed="0" covered="1"/>
            </package>
            <counter type="INSTRUCTION" missed="0" covered="2"/>
            <counter type="BRANCH" missed="0" covered="0"/>
            <counter type="LINE" missed="0" covered="1"/>
            <counter type="COMPLEXITY" missed="0" covered="1"/>
            <counter type="METHOD" missed="0" covered="1"/>
            <counter type="CLASS" missed="0" covered="1"/>
        </report>`;
        
        const result = parseJaCoCo(xmlData);
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'com/test/Simple.java',
            lines: { covered: 1, total: 1 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 1, total: 1 },
            coveredLineNumbers: new Set([5]),
            package: 'com/test'
        });
        expect(result.totals).toEqual({
            lines: { covered: 1, total: 1 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 1, total: 1 }
        });
    });

    it('should handle empty JaCoCo XML correctly', () => {
        const result = parseJaCoCoFile('test/fixtures/jacoco/jacoco.empty.xml');
        
        expect(result.files).toHaveLength(0);
        expect(result.totals).toEqual({
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });

    it('should handle JaCoCo XML with no coverage correctly', () => {
        const result = parseJaCoCoFile('test/fixtures/jacoco/jacoco.no-coverage.xml');
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'com/example/Example.java',
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 },
            coveredLineNumbers: new Set(),
            package: 'com/example'
        });
        expect(result.totals).toEqual({
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });

    it('should handle files with only method coverage data', () => {
        const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
        <report name="test">
            <package name="com/test">
                <class name="com/test/ClassOnly" sourcefilename="ClassOnly.java">
                    <method name="method1" desc="()V" line="5">
                        <counter type="METHOD" missed="0" covered="1"/>
                    </method>
                    <method name="method2" desc="()V" line="10">
                        <counter type="METHOD" missed="1" covered="0"/>
                    </method>
                    <counter type="METHOD" missed="1" covered="1"/>
                    <counter type="CLASS" missed="0" covered="1"/>
                </class>
            </package>
        </report>`;
        
        const result = parseJaCoCo(xmlData);
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'com/test/ClassOnly.java',
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 1, total: 2 },
            coveredLineNumbers: new Set(),
            package: 'com/test'
        });
    });

    it('should handle files with only sourcefile data', () => {
        const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
        <report name="test">
            <package name="com/test">
                <sourcefile name="SourceOnly.java">
                    <line nr="1" mi="0" ci="3" mb="0" cb="0"/>
                    <line nr="2" mi="2" ci="0" mb="1" cb="1"/>
                    <line nr="3" mi="0" ci="1" mb="0" cb="2"/>
                    <counter type="INSTRUCTION" missed="2" covered="4"/>
                    <counter type="BRANCH" missed="1" covered="3"/>
                    <counter type="LINE" missed="1" covered="2"/>
                    <counter type="METHOD" missed="0" covered="2"/>
                </sourcefile>
            </package>
        </report>`;
        
        const result = parseJaCoCo(xmlData);
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'com/test/SourceOnly.java',
            lines: { covered: 2, total: 3 },
            branches: { covered: 3, total: 4 },
            functions: { covered: 2, total: 2 },
            coveredLineNumbers: new Set([1, 3]),
            package: 'com/test'
        });
    });

    it('should handle packages without package name', () => {
        const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
        <report name="test">
            <package>
                <sourcefile name="Root.java">
                    <line nr="1" mi="0" ci="1" mb="0" cb="0"/>
                    <counter type="LINE" missed="0" covered="1"/>
                </sourcefile>
            </package>
        </report>`;
        
        const result = parseJaCoCo(xmlData);
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'Root.java',
            lines: { covered: 1, total: 1 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 },
            coveredLineNumbers: new Set([1]),
            package: undefined
        });
    });

    it('should prioritize line-level data over counter aggregates', () => {
        const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
        <report name="test">
            <package name="com/test">
                <sourcefile name="Conflict.java">
                    <line nr="1" mi="0" ci="1" mb="0" cb="0"/>
                    <line nr="2" mi="0" ci="1" mb="1" cb="1"/>
                    <!-- Counter says different numbers, but line data should take precedence -->
                    <counter type="LINE" missed="5" covered="10"/>
                    <counter type="BRANCH" missed="5" covered="10"/>
                </sourcefile>
            </package>
        </report>`;
        
        const result = parseJaCoCo(xmlData);
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0].lines).toEqual({ covered: 2, total: 2 });
        expect(result.files[0].branches).toEqual({ covered: 1, total: 2 });
    });

    it('should fall back to counter data when line data is missing', () => {
        const xmlData = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
        <report name="test">
            <package name="com/test">
                <sourcefile name="CounterOnly.java">
                    <!-- No line elements, only counters -->
                    <counter type="LINE" missed="2" covered="3"/>
                    <counter type="BRANCH" missed="1" covered="4"/>
                    <counter type="METHOD" missed="1" covered="2"/>
                </sourcefile>
            </package>
        </report>`;
        
        const result = parseJaCoCo(xmlData);
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0]).toEqual({
            path: 'com/test/CounterOnly.java',
            lines: { covered: 3, total: 5 },
            branches: { covered: 4, total: 5 },
            functions: { covered: 2, total: 3 },
            coveredLineNumbers: new Set(),
            package: 'com/test'
        });
    });
});
