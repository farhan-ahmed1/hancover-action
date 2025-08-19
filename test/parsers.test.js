import { describe, it, expect } from 'vitest';
import { parseLcov } from '../src/parsers/lcov';
import { parseCobertura } from '../src/parsers/cobertura';

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
});

describe('Cobertura Parser', () => {
    it('should parse a small Cobertura XML file correctly', async () => {
        const result = parseCobertura(`<?xml version="1.0" encoding="UTF-8"?>
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
</coverage>`);
        
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
});
