import { describe, it, expect } from 'vitest';
import { parseLcovFile, parseLCOV } from '../src/parsers/lcov.js';
import { parseCobertura } from '../src/parsers/cobertura.js';

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