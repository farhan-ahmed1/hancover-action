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
});
