import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { loadConfig, detectEcosystem } from '../../src/infrastructure/config.js';
import * as fs from 'fs';
import * as core from '@actions/core';

// Mock fs and core modules
vi.mock('fs');
vi.mock('@actions/core');

const mockFs = vi.mocked(fs);
const mockCore = vi.mocked(core);

describe('Phase 3: Smart Defaults and Config Integration', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockFs.existsSync.mockReturnValue(false);
        mockFs.readFileSync.mockReturnValue('{}');
        
        // Mock core functions
        mockCore.debug.mockImplementation(() => {});
        mockCore.info.mockImplementation(() => {});
        mockCore.warning.mockImplementation(() => {});
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('Smart defaults with ecosystem detection', () => {
        it('should use ecosystem-aware defaults when no config file exists', () => {
            // Simulate Node.js ecosystem
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('package.json');
            });

            const config = loadConfig('/test/node-project');

            expect(config.ui.minPassThreshold).toBe(80); // Node.js recommended threshold
            expect(config.groups).toHaveLength(4); // Node.js suggested groups
            expect(config.groups[0].name).toBe('src/components');
            expect(mockCore.debug).toHaveBeenCalledWith('Detected ecosystem: node');
        });

        it('should use ecosystem-aware defaults for Python projects', () => {
            // Simulate Python ecosystem
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('pyproject.toml');
            });

            const config = loadConfig('/test/python-project');

            expect(config.ui.minPassThreshold).toBe(85); // Python recommended threshold
            expect(config.groups).toHaveLength(3); // Python suggested groups
            expect(config.groups[0].name).toBe('src');
            expect(config.groups[1].name).toBe('tests');
        });

        it('should use ecosystem-aware defaults for Java projects', () => {
            // Simulate Java ecosystem
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('pom.xml');
            });

            const config = loadConfig('/test/java-project');

            expect(config.ui.minPassThreshold).toBe(70); // Java recommended threshold
            expect(config.groups).toHaveLength(3); // Java suggested groups
            expect(config.groups[0].name).toBe('main/java');
        });

        it('should merge user config with ecosystem-aware defaults', () => {
            // Simulate Node.js ecosystem with custom config
            mockFs.existsSync.mockImplementation((path) => {
                const pathStr = path.toString();
                return pathStr.endsWith('package.json') || pathStr.endsWith('.coverage-report.json');
            });

            mockFs.readFileSync.mockReturnValue(JSON.stringify({
                ui: {
                    minPassThreshold: 90, // Override ecosystem default
                    maxDeltaRows: 15
                },
                fallback: {
                    promoteThreshold: 0.9
                }
            }));

            const config = loadConfig('/test/node-project');

            // Should use user's override
            expect(config.ui.minPassThreshold).toBe(90);
            expect(config.ui.maxDeltaRows).toBe(15);
            expect(config.fallback.promoteThreshold).toBe(0.9);
            
            // Should still use ecosystem groups since not overridden
            expect(config.groups).toHaveLength(4);
            expect(config.groups[0].name).toBe('src/components');
        });

        it('should fallback to ecosystem defaults when config parsing fails', () => {
            // Simulate Python ecosystem with bad config
            mockFs.existsSync.mockImplementation((path) => {
                const pathStr = path.toString();
                return pathStr.endsWith('pyproject.toml') || pathStr.endsWith('.coverage-report.json');
            });

            mockFs.readFileSync.mockImplementation(() => {
                throw new Error('Invalid JSON');
            });

            const config = loadConfig('/test/python-project');

            // Should use Python ecosystem defaults despite config error
            expect(config.ui.minPassThreshold).toBe(85);
            expect(config.groups).toHaveLength(3);
            expect(mockCore.warning).toHaveBeenCalledWith(
                expect.stringContaining('Failed to load config')
            );
            expect(mockCore.warning).toHaveBeenCalledWith(
                expect.stringContaining('Using ecosystem defaults for python')
            );
        });

        it('should use generic defaults for unrecognized ecosystems', () => {
            // No ecosystem indicator files
            mockFs.existsSync.mockReturnValue(false);

            const config = loadConfig('/test/generic-project');

            expect(config.ui.minPassThreshold).toBe(50); // Generic threshold
            expect(config.groups).toHaveLength(0); // No suggested groups
            expect(mockCore.debug).toHaveBeenCalledWith('Detected ecosystem: generic');
        });
    });

    describe('Ecosystem detection integration', () => {
        it('should detect correct ecosystem and provide appropriate suggestions', () => {
            const testCases = [
                {
                    ecosystem: 'node',
                    files: ['package.json'],
                    expectedThreshold: 80,
                    expectedGroupCount: 4
                },
                {
                    ecosystem: 'java',
                    files: ['pom.xml'],
                    expectedThreshold: 70,
                    expectedGroupCount: 3
                },
                {
                    ecosystem: 'python',
                    files: ['pyproject.toml'],
                    expectedThreshold: 85,
                    expectedGroupCount: 3
                },
                {
                    ecosystem: 'dotnet',
                    files: [], // Will use file list parameter
                    inputFiles: ['test.csproj'],
                    expectedThreshold: 75,
                    expectedGroupCount: 4
                },
                {
                    ecosystem: 'go',
                    files: ['go.mod'],
                    expectedThreshold: 80,
                    expectedGroupCount: 4
                },
                {
                    ecosystem: 'ruby',
                    files: ['Gemfile'],
                    expectedThreshold: 80,
                    expectedGroupCount: 4
                }
            ];

            testCases.forEach(({ ecosystem, files, inputFiles, expectedThreshold, expectedGroupCount }) => {
                mockFs.existsSync.mockImplementation((path) => {
                    const pathStr = path.toString();
                    return files.some(file => pathStr.endsWith(file));
                });

                const result = detectEcosystem(inputFiles || [], '/test/path');

                expect(result.type).toBe(ecosystem);
                expect(result.recommendedThresholds.total).toBe(expectedThreshold);
                expect(result.suggestedGroups).toHaveLength(expectedGroupCount);
            });
        });
    });

    describe('Error handling improvements', () => {
        it('should provide better error messages with ecosystem context', () => {
            // Simulate Node.js ecosystem with config file that exists but can't be read
            mockFs.existsSync.mockImplementation((path) => {
                const pathStr = path.toString();
                return pathStr.endsWith('package.json') || pathStr.endsWith('.coverage-report.json');
            });

            mockFs.readFileSync.mockImplementation(() => {
                throw new Error('Permission denied');
            });

            const config = loadConfig('/test/node-project');

            expect(mockCore.warning).toHaveBeenCalledWith(
                expect.stringMatching(/Failed to load config.*Permission denied.*Using ecosystem defaults for node/)
            );
            
            // Should still return valid config
            expect(config.ui.minPassThreshold).toBe(80);
            expect(config.groups).toHaveLength(4);
        });
    });
});
