import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as core from '@actions/core';
import { loadConfig } from '../../src/infrastructure/config.js';

// Mock modules
vi.mock('fs');
vi.mock('@actions/core');

describe('Config Error Handling', () => {
    const mockFs = vi.mocked(fs);
    const mockCore = vi.mocked(core);

    beforeEach(() => {
        vi.resetAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should return default config when file does not exist', () => {
        // Mock file doesn't exist
        mockFs.existsSync.mockReturnValue(false);

        const config = loadConfig('/test/path');

        expect(mockFs.existsSync).toHaveBeenCalledWith('/test/path/.coverage-report.json');
        expect(mockCore.debug).toHaveBeenCalledWith('Detected ecosystem: generic');
        expect(mockCore.debug).toHaveBeenCalledWith('No .coverage-report.json found, using smart defaults for generic ecosystem');
        
        expect(config).toEqual({
            groups: [],
            fallback: {
                smartDepth: 'auto',
                promoteThreshold: 0.8
            },
            ui: {
                expandFilesFor: [],
                maxDeltaRows: 10,
                minPassThreshold: 50
            }
        });
    });

    it('should handle JSON parsing errors gracefully', () => {
        // Mock file exists but has invalid JSON
        mockFs.existsSync.mockReturnValue(true);
        mockFs.readFileSync.mockReturnValue('{ invalid json }');

        const config = loadConfig('/test/path');

        expect(mockFs.existsSync).toHaveBeenCalledWith('/test/path/.coverage-report.json');
        expect(mockFs.readFileSync).toHaveBeenCalledWith('/test/path/.coverage-report.json', 'utf8');
        expect(mockCore.warning).toHaveBeenCalledWith(
            expect.stringMatching(/Failed to load config from .*\.coverage-report\.json.*Using ecosystem defaults for/)
        );
        
        // Should return ecosystem-aware defaults (Node.js in this test environment)
        expect(config).toEqual({
            groups: [
                { name: 'src/components', patterns: ['src/components/**'] },
                { name: 'src/utils', patterns: ['src/utils/**', 'src/lib/**'] },
                { name: 'src/services', patterns: ['src/services/**', 'src/api/**'] },
                { name: 'src', patterns: ['src/**'], exclude: ['src/components/**', 'src/utils/**', 'src/lib/**', 'src/services/**', 'src/api/**'] }
            ],
            fallback: {
                smartDepth: 'auto',
                promoteThreshold: 0.8
            },
            ui: {
                expandFilesFor: ['src/components', 'src/utils', 'src/services', 'src'],
                maxDeltaRows: 10,
                minPassThreshold: 80
            }
        });
    });

    it('should handle file reading errors gracefully', () => {
        // Mock file exists but reading throws an error
        mockFs.existsSync.mockReturnValue(true);
        mockFs.readFileSync.mockImplementation(() => {
            throw new Error('Permission denied');
        });

        const config = loadConfig('/test/path');

        expect(mockFs.existsSync).toHaveBeenCalledWith('/test/path/.coverage-report.json');
        expect(mockFs.readFileSync).toHaveBeenCalledWith('/test/path/.coverage-report.json', 'utf8');
        expect(mockCore.warning).toHaveBeenCalledWith(
            expect.stringMatching(/Failed to load config from .*\.coverage-report\.json.*Permission denied.*Using ecosystem defaults for/)
        );
        
        // Should return ecosystem-aware defaults (Node.js in this test environment)
        expect(config).toEqual({
            groups: [
                { name: 'src/components', patterns: ['src/components/**'] },
                { name: 'src/utils', patterns: ['src/utils/**', 'src/lib/**'] },
                { name: 'src/services', patterns: ['src/services/**', 'src/api/**'] },
                { name: 'src', patterns: ['src/**'], exclude: ['src/components/**', 'src/utils/**', 'src/lib/**', 'src/services/**', 'src/api/**'] }
            ],
            fallback: {
                smartDepth: 'auto',
                promoteThreshold: 0.8
            },
            ui: {
                expandFilesFor: ['src/components', 'src/utils', 'src/services', 'src'],
                maxDeltaRows: 10,
                minPassThreshold: 80
            }
        });
    });

    it('should load valid config with partial fields', () => {
        // Mock file exists with partial config
        const partialConfig = {
            fallback: {
                smartDepth: 'top' as const
            }
        };
        
        mockFs.existsSync.mockReturnValue(true);
        mockFs.readFileSync.mockReturnValue(JSON.stringify(partialConfig));

        const config = loadConfig('/test/path');

        expect(mockFs.existsSync).toHaveBeenCalledWith('/test/path/.coverage-report.json');
        expect(mockFs.readFileSync).toHaveBeenCalledWith('/test/path/.coverage-report.json', 'utf8');
        expect(mockCore.info).toHaveBeenCalledWith('Loaded config from /test/path/.coverage-report.json');
        expect(mockCore.debug).toHaveBeenCalledWith(expect.stringMatching(/Config:/));
        
        // Should use ecosystem-aware defaults (Node.js detected based on package.json)
        expect(config).toEqual({
            groups: [
                { name: 'src/components', patterns: ['src/components/**'] },
                { name: 'src/utils', patterns: ['src/utils/**', 'src/lib/**'] },
                { name: 'src/services', patterns: ['src/services/**', 'src/api/**'] },
                { name: 'src', patterns: ['src/**'], exclude: ['src/components/**', 'src/utils/**', 'src/lib/**', 'src/services/**', 'src/api/**'] }
            ],
            fallback: {
                smartDepth: 'top', // from config file
                promoteThreshold: 0.8
            },
            ui: {
                expandFilesFor: ['src/components', 'src/utils', 'src/services', 'src'], 
                maxDeltaRows: 10,
                minPassThreshold: 80 // Node.js ecosystem default
            }
        });
    });

    it('should load valid config with all fields', () => {
        // Mock file exists with complete config
        const fullConfig = {
            groups: [
                { name: 'test', patterns: ['test/**'] }
            ],
            fallback: {
                smartDepth: 'two' as const,
                promoteThreshold: 0.9
            },
            ui: {
                expandFilesFor: ['test'],
                maxDeltaRows: 20,
                minPassThreshold: 80
            }
        };
        
        mockFs.existsSync.mockReturnValue(true);
        mockFs.readFileSync.mockReturnValue(JSON.stringify(fullConfig));

        const config = loadConfig('/test/path');

        expect(mockFs.existsSync).toHaveBeenCalledWith('/test/path/.coverage-report.json');
        expect(mockFs.readFileSync).toHaveBeenCalledWith('/test/path/.coverage-report.json', 'utf8');
        expect(mockCore.info).toHaveBeenCalledWith('Loaded config from /test/path/.coverage-report.json');
        expect(mockCore.debug).toHaveBeenCalledWith(expect.stringMatching(/Config:/));
        
        // Should use loaded config
        expect(config).toEqual(fullConfig);
    });

    it('should handle empty config file', () => {
        // Mock file exists but is empty object
        mockFs.existsSync.mockReturnValue(true);
        mockFs.readFileSync.mockReturnValue('{}');

        const config = loadConfig('/test/path');

        // Should use ecosystem-aware defaults (Node.js detected based on package.json)
        expect(config).toEqual({
            groups: [
                { name: 'src/components', patterns: ['src/components/**'] },
                { name: 'src/utils', patterns: ['src/utils/**', 'src/lib/**'] },
                { name: 'src/services', patterns: ['src/services/**', 'src/api/**'] },
                { name: 'src', patterns: ['src/**'], exclude: ['src/components/**', 'src/utils/**', 'src/lib/**', 'src/services/**', 'src/api/**'] }
            ],
            fallback: {
                smartDepth: 'auto', // from defaults
                promoteThreshold: 0.8 // from defaults
            },
            ui: {
                expandFilesFor: ['src/components', 'src/utils', 'src/services', 'src'],
                maxDeltaRows: 10, // from defaults
                minPassThreshold: 80 // Node.js ecosystem default
            }
        });
    });
});
