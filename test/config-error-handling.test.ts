import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as core from '@actions/core';
import { loadConfig } from '../src/config.js';

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
        expect(mockCore.debug).toHaveBeenCalledWith('No .coverage-report.json found, using smart defaults');
        
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
            expect.stringMatching(/Failed to load config from .*\.coverage-report\.json.*Using defaults/)
        );
        
        // Should return default config
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
            expect.stringMatching(/Failed to load config from .*\.coverage-report\.json.*Permission denied.*Using defaults/)
        );
        
        // Should return default config
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
        
        // Should merge with defaults
        expect(config).toEqual({
            groups: [], // from defaults
            fallback: {
                smartDepth: 'top', // from loaded config
                promoteThreshold: 0.8 // from defaults
            },
            ui: {
                expandFilesFor: [], // from defaults
                maxDeltaRows: 10, // from defaults
                minPassThreshold: 50 // from defaults
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

        expect(config).toEqual({
            groups: [], // from defaults
            fallback: {
                smartDepth: 'auto', // from defaults
                promoteThreshold: 0.8 // from defaults
            },
            ui: {
                expandFilesFor: [], // from defaults
                maxDeltaRows: 10, // from defaults
                minPassThreshold: 50 // from defaults
            }
        });
    });
});
