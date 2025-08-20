import { describe, it, expect } from 'vitest';
import { parseAnyCoverage, parseAnyCoverageContent } from '../../src/parsers/index.js';

describe('Parser Auto-Detection', () => {
    describe('File-based Auto-detection', () => {
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
            expect(result.files.length).toBeGreaterThan(0);
        });

        it('should handle empty files gracefully', async () => {
            const result = await parseAnyCoverage('test/fixtures/clover.empty.xml');
            expect(result.files).toHaveLength(0);
            expect(result.totals).toEqual({
                lines: { covered: 0, total: 0 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 0, total: 0 }
            });
        });
    });

    describe('Content-based Auto-detection', () => {
        it('should auto-detect Clover from content with hint', () => {
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

        it('should auto-detect LCOV from content', () => {
            const lcovContent = `SF:src/test.js
DA:1,5
DA:2,0
DA:3,2
end_of_record`;
            
            const result = parseAnyCoverageContent(lcovContent);
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('src/test.js');
        });

        it('should auto-detect Cobertura from content', () => {
            const coberturaContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0" line-rate="0.66667" branch-rate="0.5">
    <packages>
        <package name="src">
            <classes>
                <class name="example1.js" filename="src/example1.js">
                    <lines>
                        <line number="1" hits="1"/>
                        <line number="2" hits="0"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseAnyCoverageContent(coberturaContent);
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('src/example1.js');
        });

        it('should distinguish between Clover and Cobertura XML', () => {
            // Clover XML
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
            
            // Cobertura XML
            const coberturaContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="src">
            <classes>
                <class filename="src/test.js">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const cloverResult = parseAnyCoverageContent(cloverContent);
            const coberturaResult = parseAnyCoverageContent(coberturaContent);
            
            // Both should parse successfully but may have different structures
            expect(cloverResult.files).toHaveLength(1);
            expect(coberturaResult.files).toHaveLength(1);
            
            // Clover includes package information
            expect(cloverResult.files[0].package).toBeDefined();
        });

        it('should handle malformed content gracefully', () => {
            const malformedContent = 'This is not coverage data';
            
            // Should attempt to parse as LCOV and may return empty results rather than throw
            const result = parseAnyCoverageContent(malformedContent);
            expect(result.files).toHaveLength(0);
        });

        it('should handle empty content', () => {
            const emptyContent = '';
            
            // Should attempt to parse as LCOV and return empty results
            const result = parseAnyCoverageContent(emptyContent);
            expect(result.files).toHaveLength(0);
        });
    });

    describe('Format Priority & Edge Cases', () => {
        it('should handle XML without clear format indicators', () => {
            const ambiguousXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage>
    <data>
        <file path="test.js"/>
    </data>
</coverage>`;
            
            // Should attempt parsing as Cobertura (default for XML coverage) and return empty results
            const result = parseAnyCoverageContent(ambiguousXml);
            expect(result.files).toHaveLength(0);
        });

        it('should prioritize explicit format hints', () => {
            const lcovLikeContent = `SF:test.js
DA:1,1
end_of_record`;
            
            // Force parse as LCOV even though content could be ambiguous
            const result = parseAnyCoverageContent(lcovLikeContent, 'lcov');
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('test.js');
        });
    });

    describe('Error Handling and Edge Cases', () => {
        it('should handle non-existent files', async () => {
            await expect(parseAnyCoverage('non-existent-file.xml')).rejects.toThrow();
        });

        it('should handle files with non-standard extensions that trigger fallback detection', async () => {
            // Test with a file that doesn't end in .info, .lcov, or .xml
            await expect(parseAnyCoverage('non-existent-file.txt')).rejects.toThrow();
        });

        it('should handle files with .lcov extension explicitly', async () => {
            // Test the .lcov extension detection path
            const result = await parseAnyCoverage('test/fixtures/test.lcov');
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('sample/file/path');
        });

        it('should handle files with non-standard extensions using content detection', async () => {
            // Test fallback content detection for a .cov file
            const result = await parseAnyCoverage('test/fixtures/test.cov');
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('sample/file/path');
        });

        it('should handle XML files that trigger Clover detection', async () => {
            const result = await parseAnyCoverage('test/fixtures/clover.small.xml');
            expect(result.files).toHaveLength(1);
            expect(result.files[0].package).toBe('src');
        });

        it('should handle XML files with DOCTYPE declarations', async () => {
            // Create a temporary file path that triggers XML detection
            const result = await parseAnyCoverage('test/fixtures/cobertura.small.xml');
            expect(result.files.length).toBeGreaterThan(0);
        });

        it('should handle XML files that look like Clover but default to Cobertura', async () => {
            // Test XML files that don't clearly match either format
            const result = await parseAnyCoverage('test/fixtures/cobertura.empty.xml');
            expect(result.files).toHaveLength(0);
        });

        it('should handle malicious XML files gracefully', async () => {
            // Test with malicious content that might cause parsing errors
            const result = await parseAnyCoverage('test/fixtures/clover.malicious.xml');
            // Should not throw, might return empty results
            expect(result).toBeDefined();
        });

        it('should handle malicious LCOV files gracefully', async () => {
            const result = await parseAnyCoverage('test/fixtures/lcov.malicious.info');
            // Should not throw, might return empty results
            expect(result).toBeDefined();
        });

        it('should handle files that trigger fallback content sniffing for XML', async () => {
            // Use an XML file that doesn't clearly match either format
            const result = await parseAnyCoverage('test/fixtures/xml-no-indicators.xml');
            expect(result).toBeDefined();
            // Should default to Cobertura and likely return empty results
            expect(result.files).toHaveLength(0);
        });

        it('should handle files that trigger fallback content sniffing for LCOV', async () => {
            // Use an existing LCOV file to test fallback detection
            const result = await parseAnyCoverage('test/fixtures/lcov.sample.info');
            expect(result).toBeDefined();
        });

        it('should handle fallback detection with TN: marker', async () => {
            // Test fallback content detection for LCOV with TN: marker
            const result = await parseAnyCoverage('test/fixtures/test-tn.txt');
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('src/test.js');
        });

        it('should handle fallback detection for Cobertura with DOCTYPE reference', async () => {
            // Test fallback content detection that triggers Cobertura path
            const result = await parseAnyCoverage('test/fixtures/doctype-reference.txt');
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('src/test.js');
        });

        it('should default to Cobertura for XML files with no clear indicators', async () => {
            // This should trigger the default Cobertura path for XML files (line with parseCoberturaFile)
            const result = await parseAnyCoverage('test/fixtures/xml-no-indicators.xml');
            expect(result).toBeDefined();
            // Will likely return empty results since it's not valid Cobertura
            expect(result.files).toHaveLength(0);
        });

        it('should detect Clover in fallback content detection', async () => {
            // This should trigger the Clover detection path in fallback logic
            const result = await parseAnyCoverage('test/fixtures/xml-clover-like.txt');
            expect(result).toBeDefined();
            // Will likely return empty results since it's not valid Clover
            expect(result.files).toHaveLength(0);
        });

        it('should default to LCOV for unrecognized content', async () => {
            // This should trigger the final LCOV fallback path using truly unrecognized content
            const result = await parseAnyCoverage('test/fixtures/unrecognized.txt');
            expect(result).toBeDefined();
            // Will return empty results since it's not valid LCOV
            expect(result.files).toHaveLength(0);
        });

        it('should handle XML file reading errors gracefully', async () => {
            // Test error handling by using a non-existent file with .xml extension
            await expect(parseAnyCoverage('test/fixtures/non-existent.xml')).rejects.toThrow('Failed to auto-detect XML coverage format');
        });

        it('should handle fallback file reading errors gracefully', async () => {
            // Test error handling by using a non-existent file with non-standard extension
            await expect(parseAnyCoverage('test/fixtures/non-existent.unknown')).rejects.toThrow('Failed to auto-detect coverage format');
        });

        it('should handle fallback Cobertura detection', async () => {
            // Use existing empty XML file to test fallback Cobertura detection
            const result = await parseAnyCoverage('test/fixtures/cobertura.empty.xml');
            expect(result).toBeDefined();
            expect(result.files).toHaveLength(0); // Empty coverage XML should return no files
        });
    });

    describe('Content Detection Fallback Logic', () => {
        it('should handle content with XML DOCTYPE for Cobertura', () => {
            const coberturaWithDoctype = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="src">
            <classes>
                <class filename="src/test.js">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseAnyCoverageContent(coberturaWithDoctype);
            expect(result.files).toHaveLength(1);
        });

        it('should detect Cobertura from content with DOCTYPE reference (fallback test)', () => {
            // Test content that includes DOCTYPE in a comment to trigger detection
            const contentWithDoctypeReference = `<!-- <!DOCTYPE coverage --> 
<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="src">
            <classes>
                <class filename="src/test.js">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseAnyCoverageContent(contentWithDoctypeReference);
            expect(result.files).toHaveLength(1);
        });

        it('should handle content that includes both coverage and project tags for Clover', () => {
            const cloverWithProject = `<?xml version="1.0" encoding="UTF-8"?>
<coverage>
    <project timestamp="1234567890">
        <package name="test">
            <file name="test.js" path="src/test.js">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
            
            const result = parseAnyCoverageContent(cloverWithProject);
            expect(result.files).toHaveLength(1);
        });

        it('should handle content with generator="clover" attribute', () => {
            const cloverWithGenerator = `<?xml version="1.0" encoding="UTF-8"?>
<coverage generator="clover" clover="4.4.1">
    <project>
        <package name="test">
            <file name="test.js" path="src/test.js">
                <line num="1" type="stmt" count="1"/>
            </file>
        </package>
    </project>
</coverage>`;
            
            const result = parseAnyCoverageContent(cloverWithGenerator);
            expect(result.files).toHaveLength(1);
        });

        it('should handle LCOV content with TN: marker', () => {
            const lcovWithTN = `TN:test-name
SF:src/test.js
DA:1,5
DA:2,0
end_of_record`;
            
            const result = parseAnyCoverageContent(lcovWithTN);
            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('src/test.js');
        });

        it('should handle content with explicit cobertura hint', () => {
            const coberturaContent = `<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0">
    <packages>
        <package name="src">
            <classes>
                <class filename="src/test.js">
                    <lines>
                        <line number="1" hits="1"/>
                    </lines>
                </class>
            </classes>
        </package>
    </packages>
</coverage>`;
            
            const result = parseAnyCoverageContent(coberturaContent, 'cobertura');
            expect(result.files).toHaveLength(1);
        });

        it('should handle plain text content without any format markers', () => {
            const plainContent = 'Some random text that is not coverage data at all';
            
            // Should default to LCOV parsing and return empty results
            const result = parseAnyCoverageContent(plainContent);
            expect(result.files).toHaveLength(0);
        });
    });
});
