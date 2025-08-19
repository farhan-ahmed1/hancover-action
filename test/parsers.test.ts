import { describe, it, expect } from 'vitest';
import { parseLcov, parseLCOV } from '../src/parsers/lcov.js';
import { parseCobertura } from '../src/parsers/cobertura.js';

describe('LCOV Parser', () => {
    it('should parse a small LCOV file correctly', async () => {
        const result = parseLcov('test/fixtures/lcov.small.info');
        
        expect(result).toEqual({
            path: 'sample/file/path',
            lines: [
                { line: 1, hits: 1 },
                { line: 2, hits: 0 },
                { line: 3, hits: 1 },
                { line: 4, hits: 1 },
                { line: 5, hits: 0 },
                { line: 6, hits: 1 },
                { line: 7, hits: 1 },
                { line: 8, hits: 1 },
                { line: 9, hits: 0 },
                { line: 10, hits: 1 }
            ],
            summary: {
                linesCovered: 7,
                linesTotal: 10
            }
        });
    });

    it('should parse LCOV data string correctly', () => {
        const lcovData = `SF:src/test.js
DA:1,5
DA:2,0
DA:3,2
end_of_record`;
        
        const result = parseLCOV(lcovData);
        expect(result).toHaveLength(1);
        expect(result[0]).toEqual({
            path: 'src/test.js',
            lines: [
                { line: 1, hits: 5 },
                { line: 2, hits: 0 },
                { line: 3, hits: 2 }
            ],
            summary: {
                linesCovered: 2,
                linesTotal: 3
            }
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
            lines: [
                { line: 1, hits: 1 },
                { line: 2, hits: 0 },
                { line: 3, hits: 1 }
            ],
            summary: {
                linesCovered: 2,
                linesTotal: 3
            }
        });
    });

    it('should handle empty XML correctly', () => {
        const emptyXml = '<?xml version="1.0" encoding="UTF-8"?><coverage></coverage>';
        const result = parseCobertura(emptyXml);
        expect(result.files).toHaveLength(0);
    });
});