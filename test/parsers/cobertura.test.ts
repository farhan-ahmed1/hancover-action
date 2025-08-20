import { describe, it, expect } from 'vitest';
import { parseCobertura, parseCoberturaFile } from '../../src/parsers/cobertura.js';

describe('Cobertura Parser - Core Functionality', () => {
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
            coveredLineNumbers: new Set([1, 3]),
            package: 'src'
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

    it('should parse Cobertura from sample fixture', async () => {
        const result = parseCoberturaFile('test/fixtures/cobertura/cobertura.sample.xml');
        
        expect(result.files).toHaveLength(2);
        expect(result.files[0].path).toBe('src/utils.js');
        expect(result.files[1].path).toBe('src/helpers.js');
        
        // Check totals
        expect(result.totals.lines.total).toBe(9); // 6 + 3 lines
        expect(result.totals.lines.covered).toBe(6); // 4 + 2 covered lines
        expect(result.totals.branches.total).toBe(2); // 2 branches from condition-coverage
        expect(result.totals.branches.covered).toBe(1); // 1 covered branch
        expect(result.totals.functions.total).toBe(3); // 3 methods total
        expect(result.totals.functions.covered).toBe(3); // 3 methods with covered lines
    });

    it('should parse complex Cobertura from fixture', async () => {
        const result = parseCoberturaFile('test/fixtures/cobertura/cobertura.complex.xml');
        
        expect(result.files).toHaveLength(3);
        
        // Verify file paths and packages
        const calculatorFile = result.files.find(f => f.path === 'src/Calculator.java');
        expect(calculatorFile).toBeDefined();
        expect(calculatorFile?.package).toBe('com.example');
        
        const utilsFile = result.files.find(f => f.path === 'src/utils/StringUtils.java');
        expect(utilsFile).toBeDefined();
        expect(utilsFile?.package).toBe('com.example');
        
        const testFile = result.files.find(f => f.path === 'test/TestHelper.java');
        expect(testFile).toBeDefined();
        expect(testFile?.package).toBe('com.test');
        
        // Verify totals
        expect(result.totals.lines.total).toBe(17); // Sum of all lines
        expect(result.totals.lines.covered).toBe(11); // Sum of covered lines (5+4+2)
        expect(result.totals.functions.total).toBe(6); // Sum of all methods (3+1+2)
        expect(result.totals.functions.covered).toBe(4); // Methods with covered lines (add+divide+format+setup)
        expect(result.totals.branches.total).toBe(12); // 2+10+0 branches
        expect(result.totals.branches.covered).toBe(8); // 1+7+0 covered branches
    });

    it('should handle branch coverage in Cobertura', () => {
        const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0" line-rate="0.5" branch-rate="0.5">
    <packages>
        <package name="src">
            <classes>
                <class name="branches.js" filename="src/branches.js">
                    <lines>
                        <line number="1" hits="5" branch="true" condition-coverage="50% (1/2)">
                            <conditions>
                                <condition number="0" type="jump" coverage="50%"/>
                            </conditions>
                        </line>
                        <line number="2" hits="0"/>
                        <line number="3" hits="3" branch="true" condition-coverage="100% (3/3)"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
        
        const result = parseCobertura(xmlContent);
        expect(result.files).toHaveLength(1);
        expect(result.files[0].lines).toEqual({ covered: 2, total: 3 });
        expect(result.files[0].branches.total).toBe(5); // 2 + 3 branches
        expect(result.files[0].branches.covered).toBe(4); // 1 + 3 covered branches
    });

    it('should handle method coverage in Cobertura', () => {
        const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="src">
            <classes>
                <class name="methods.js" filename="src/methods.js">
                    <methods>
                        <method name="func1" signature="()" line-rate="1.0" branch-rate="1.0">
                            <lines>
                                <line number="1" hits="1"/>
                            </lines>
                        </method>
                        <method name="func2" signature="()" line-rate="0.0" branch-rate="1.0">
                            <lines>
                                <line number="5" hits="0"/>
                            </lines>
                        </method>
                        <method name="func3" signature="()" line-rate="0.5" branch-rate="1.0">
                            <lines>
                                <line number="10" hits="2"/>
                                <line number="11" hits="0"/>
                            </lines>
                        </method>
                    </methods>
                    <lines>
                        <line number="1" hits="1"/>
                        <line number="5" hits="0"/>
                        <line number="10" hits="2"/>
                        <line number="11" hits="0"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
        
        const result = parseCobertura(xmlContent);
        expect(result.files).toHaveLength(1);
        expect(result.files[0].functions).toEqual({ covered: 2, total: 3 }); // func1 and func3 have covered lines
        expect(result.files[0].lines).toEqual({ covered: 2, total: 4 });
    });

    it('should handle malformed XML gracefully', () => {
        const malformedXml = '<?xml version="1.0"?><coverage><invalid></coverage>';
        
        // Should not throw, but return empty result
        const result = parseCobertura(malformedXml);
        expect(result.files).toHaveLength(0);
    });

    it('should handle coverage without packages', () => {
        const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0" line-rate="1.0" branch-rate="1.0">
</coverage>`;
        
        const result = parseCobertura(xmlContent);
        expect(result.files).toHaveLength(0);
        expect(result.totals).toEqual({
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        });
    });

    it('should handle different package structures', () => {
        const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="com.example.deep.package">
            <classes>
                <class name="DeepClass" filename="src/deep/DeepClass.java">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
        <package name="">
            <classes>
                <class name="RootClass" filename="RootClass.java">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
        
        const result = parseCobertura(xmlContent);
        expect(result.files).toHaveLength(2);
        
        const deepFile = result.files.find(f => f.path === 'src/deep/DeepClass.java');
        expect(deepFile).toBeDefined();
        expect(deepFile?.package).toBe('com.example.deep.package');
        
        const rootFile = result.files.find(f => f.path === 'RootClass.java');
        expect(rootFile).toBeDefined();
        expect(rootFile?.package).toBe('');
    });

    it('should handle zero hit counts correctly', () => {
        const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="zero">
            <classes>
                <class name="ZeroTest" filename="src/zero.js">
                    <lines>
                        <line number="1" hits="0"/>
                        <line number="2" hits="0"/>
                        <line number="3" hits="0"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
        
        const result = parseCobertura(xmlContent);
        expect(result.files).toHaveLength(1);
        expect(result.files[0].lines).toEqual({ covered: 0, total: 3 });
        expect(result.files[0].coveredLineNumbers.size).toBe(0);
    });
});
