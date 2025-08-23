import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { collectCoverage } from '../src/processing/normalize.js';
import { globby } from 'globby';
import { statSync, readFileSync } from 'fs';
import * as core from '@actions/core';

// Mock dependencies
vi.mock('globby');
vi.mock('fs');
vi.mock('@actions/core');
vi.mock('../src/parsers/index.js', () => ({
    parseAnyCoverageContent: vi.fn()
}));
vi.mock('../src/infrastructure/fs-limits.js', () => ({
    enforceFileSizeLimits: vi.fn(),
    enforceTotalSizeLimits: vi.fn()
}));

const mockGlobby = vi.mocked(globby);
const mockStatSync = vi.mocked(statSync);
const mockReadFileSync = vi.mocked(readFileSync);
const mockCoreWarning = vi.mocked(core.warning);

describe('normalize', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.resetAllMocks();
    });

    describe('collectCoverage', () => {
        it('should collect coverage from LCOV files', async () => {
            const mockStats = { size: 1000 };
            const mockLcovContent = `
TN:
SF:/path/to/file.js
FNF:1
FNH:1
LF:10
LH:8
end_of_record
            `.trim();

            mockGlobby.mockResolvedValue(['coverage.info']);
            mockStatSync.mockReturnValue(mockStats as any);
            mockReadFileSync.mockReturnValue(mockLcovContent);

            const { parseAnyCoverageContent } = await import('../src/parsers/index.js');
            vi.mocked(parseAnyCoverageContent).mockReturnValue({
                files: [{
                    path: '/path/to/file.js',
                    lines: { covered: 8, total: 10 },
                    functions: { covered: 1, total: 1 },
                    branches: { covered: 0, total: 0 },
                    coveredLineNumbers: new Set([1, 2, 3, 4, 5, 6, 7, 8])
                }],
                totals: {
                    lines: { covered: 8, total: 10 },
                    functions: { covered: 1, total: 1 },
                    branches: { covered: 0, total: 0 }
                }
            });

            const result = await collectCoverage(['coverage.info']);

            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('/path/to/file.js');
        });

        it('should collect coverage from Cobertura XML files', async () => {
            const mockStats = { size: 2000 };
            const mockXmlContent = `
<?xml version="1.0" ?>
<coverage>
    <packages>
        <package name="src">
            <classes>
                <class filename="file.js" line-rate="0.8" branch-rate="0.6">
                </class>
            </classes>
        </package>
    </packages>
</coverage>
            `.trim();

            mockGlobby.mockResolvedValue(['coverage.xml']);
            mockStatSync.mockReturnValue(mockStats as any);
            mockReadFileSync.mockReturnValue(mockXmlContent);

            const { parseAnyCoverageContent } = await import('../src/parsers/index.js');
            vi.mocked(parseAnyCoverageContent).mockReturnValue({
                files: [{
                    path: 'file.js',
                    lines: { covered: 8, total: 10 },
                    functions: { covered: 1, total: 1 },
                    branches: { covered: 3, total: 5 },
                    coveredLineNumbers: new Set([1, 2, 3, 4, 5, 6, 7, 8])
                }],
                totals: {
                    lines: { covered: 8, total: 10 },
                    functions: { covered: 1, total: 1 },
                    branches: { covered: 3, total: 5 }
                }
            });

            const result = await collectCoverage(['coverage.xml']);

            expect(result.files).toHaveLength(1);
            expect(result.files[0].path).toBe('file.js');
        });

        it('should handle file size limits', async () => {
            const mockStats = { size: 60000000 }; // 60MB - exceeds default limit
            
            mockGlobby.mockResolvedValue(['large-file.xml']);
            mockStatSync.mockReturnValue(mockStats as any);

            const { enforceFileSizeLimits } = await import('../src/infrastructure/fs-limits.js');
            vi.mocked(enforceFileSizeLimits).mockImplementation((size, limit) => {
                if (limit && size > limit) {
                    throw new Error('File too large');
                }
            });

            const result = await collectCoverage(['large-file.xml']);

            expect(result.files).toHaveLength(0);
            expect(mockCoreWarning).toHaveBeenCalledWith(
                expect.stringContaining('Skipping file large-file.xml')
            );
        });

        it('should handle total size limits', async () => {
            const mockStats1 = { size: 100000000 }; // 100MB
            const mockStats2 = { size: 150000000 }; // 150MB - would exceed total limit
            
            mockGlobby.mockResolvedValue(['file1.xml', 'file2.xml']);
            mockStatSync
                .mockReturnValueOnce(mockStats1 as any)
                .mockReturnValueOnce(mockStats2 as any);
            
            mockReadFileSync.mockReturnValue('<coverage></coverage>');

            const { enforceFileSizeLimits, enforceTotalSizeLimits } = await import('../src/infrastructure/fs-limits.js');
            vi.mocked(enforceFileSizeLimits).mockImplementation(() => {}); // Allow individual files
            vi.mocked(enforceTotalSizeLimits)
                .mockImplementationOnce(() => {}) // First file OK
                .mockImplementationOnce(() => {
                    throw new Error('Total size limit exceeded');
                }); // Second file exceeds total

            const { parseAnyCoverageContent } = await import('../src/parsers/index.js');
            vi.mocked(parseAnyCoverageContent).mockReturnValue({
                files: [],
                totals: {
                    lines: { covered: 0, total: 0 },
                    functions: { covered: 0, total: 0 },
                    branches: { covered: 0, total: 0 }
                }
            });

            await collectCoverage(['file1.xml', 'file2.xml']);

            expect(mockCoreWarning).toHaveBeenCalledWith(
                expect.stringContaining('Skipping file file2.xml')
            );
        });

        it('should throw in strict mode when file size limits are exceeded', async () => {
            const mockStats = { size: 60000000 }; // 60MB
            
            mockGlobby.mockResolvedValue(['large-file.xml']);
            mockStatSync.mockReturnValue(mockStats as any);

            const { enforceFileSizeLimits } = await import('../src/infrastructure/fs-limits.js');
            vi.mocked(enforceFileSizeLimits).mockImplementation(() => {
                throw new Error('File too large');
            });

            await expect(collectCoverage(['large-file.xml'], 52428800, 209715200, true))
                .rejects.toThrow('File too large');
        });

        it('should limit to 1000 files maximum', async () => {
            const manyFiles = Array.from({ length: 1500 }, (_, i) => `file${i}.xml`);
            const mockStats = { size: 1000 };
            
            mockGlobby.mockResolvedValue(manyFiles);
            mockStatSync.mockReturnValue(mockStats as any);
            mockReadFileSync.mockReturnValue('<coverage></coverage>');

            const { parseAnyCoverageContent } = await import('../src/parsers/index.js');
            vi.mocked(parseAnyCoverageContent).mockReturnValue({
                files: [],
                totals: {
                    lines: { covered: 0, total: 0 },
                    functions: { covered: 0, total: 0 },
                    branches: { covered: 0, total: 0 }
                }
            });

            await collectCoverage(['**/*.xml']);

            // Should only process first 1000 files
            expect(mockStatSync).toHaveBeenCalledTimes(1000);
        });

        it('should handle empty glob results', async () => {
            mockGlobby.mockResolvedValue([]);

            const result = await collectCoverage(['no-match-*.xml']);

            expect(result.files).toHaveLength(0);
        });

        it('should handle file read errors in non-strict mode', async () => {
            const mockStats = { size: 1000 };
            
            mockGlobby.mockResolvedValue(['broken-file.xml']);
            mockStatSync.mockReturnValue(mockStats as any);
            mockReadFileSync.mockImplementation(() => {
                throw new Error('Permission denied');
            });

            const result = await collectCoverage(['broken-file.xml']);

            expect(result.files).toHaveLength(0);
        });

        it('should handle parse errors in non-strict mode', async () => {
            const mockStats = { size: 1000 };
            
            mockGlobby.mockResolvedValue(['invalid-file.xml']);
            mockStatSync.mockReturnValue(mockStats as any);
            mockReadFileSync.mockReturnValue('invalid content');

            const { parseAnyCoverageContent } = await import('../src/parsers/index.js');
            vi.mocked(parseAnyCoverageContent).mockImplementation(() => {
                throw new Error('Parse error');
            });

            const result = await collectCoverage(['invalid-file.xml']);

            expect(result.files).toHaveLength(0);
        });

        it('should auto-detect LCOV format from file extension', async () => {
            const mockStats = { size: 1000 };
            const mockContent = 'TN:\nend_of_record';
            
            mockGlobby.mockResolvedValue(['coverage.info']);
            mockStatSync.mockReturnValue(mockStats as any);
            mockReadFileSync.mockReturnValue(mockContent);

            const { parseAnyCoverageContent } = await import('../src/parsers/index.js');
            vi.mocked(parseAnyCoverageContent).mockReturnValue({
                files: [],
                totals: {
                    lines: { covered: 0, total: 0 },
                    functions: { covered: 0, total: 0 },
                    branches: { covered: 0, total: 0 }
                }
            });

            await collectCoverage(['coverage.info']);

            expect(parseAnyCoverageContent).toHaveBeenCalledWith(mockContent, 'lcov');
        });

        it('should auto-detect Cobertura format from XML content', async () => {
            const mockStats = { size: 1000 };
            const mockContent = '<?xml version="1.0"?><coverage></coverage>';
            
            mockGlobby.mockResolvedValue(['report.xml']);
            mockStatSync.mockReturnValue(mockStats as any);
            mockReadFileSync.mockReturnValue(mockContent);

            const { parseAnyCoverageContent } = await import('../src/parsers/index.js');
            vi.mocked(parseAnyCoverageContent).mockReturnValue({
                files: [],
                totals: {
                    lines: { covered: 0, total: 0 },
                    functions: { covered: 0, total: 0 },
                    branches: { covered: 0, total: 0 }
                }
            });

            await collectCoverage(['report.xml']);

            expect(parseAnyCoverageContent).toHaveBeenCalledWith(mockContent, 'cobertura');
        });
    });
});
