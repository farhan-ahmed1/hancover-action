import { describe, it, expect } from 'vitest';
import { parseAnyCoverage, parseAnyCoverageContent } from '../../src/parsers/index.js';

describe('Unified Parser', () => {
    it('should auto-detect and parse LCOV files', async () => {
        const result = await parseAnyCoverage('test/fixtures/lcov/lcov.small.info');
        
        expect(result.files).toHaveLength(1);
        expect(result.files[0].path).toBe('sample/file/path');
        expect(result.totals.lines.total).toBe(10);
        expect(result.totals.lines.covered).toBe(7);
    });

    it('should auto-detect and parse Cobertura files', async () => {
        const result = await parseAnyCoverage('test/fixtures/cobertura/cobertura.sample.xml');
        
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

    it('should parse content with format hints', () => {
        const lcovData = `SF:src/test.js
DA:1,5
DA:2,0
end_of_record`;
        
        const result = parseAnyCoverageContent(lcovData, 'lcov');
        expect(result.files).toHaveLength(1);
        expect(result.files[0].path).toBe('src/test.js');
        expect(result.totals.lines.total).toBe(2);
        expect(result.totals.lines.covered).toBe(1);
    });

    it('should auto-detect format from content', () => {
        // Should detect LCOV format
        const lcovData = `SF:src/test.js
DA:1,5
end_of_record`;
        
        const lcovResult = parseAnyCoverageContent(lcovData);
        expect(lcovResult.files).toHaveLength(1);
        expect(lcovResult.files[0].path).toBe('src/test.js');

        // Should detect Cobertura format
        const xmlData = `<?xml version="1.0"?>
<coverage><packages></packages></coverage>`;
        
        const xmlResult = parseAnyCoverageContent(xmlData);
        expect(xmlResult.files).toHaveLength(0);
        expect(xmlResult.totals.lines.total).toBe(0);
    });
});
