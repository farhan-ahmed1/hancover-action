import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import { detectEcosystem } from '../src/infrastructure/config.js';

// Mock fs module
vi.mock('fs');
const mockFs = vi.mocked(fs);

describe('Ecosystem Detection', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Default to no files existing
        mockFs.existsSync.mockReturnValue(false);
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('detectEcosystem', () => {
        it('should detect Node.js ecosystem when package.json exists', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('package.json');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('node');
            expect(ecosystem.recommendedThresholds.total).toBe(80);
            expect(ecosystem.recommendedThresholds.changes).toBe(85);
            expect(ecosystem.suggestedGroups).toEqual([
                { name: 'src/components', patterns: ['src/components/**'] },
                { name: 'src/utils', patterns: ['src/utils/**', 'src/lib/**'] },
                { name: 'src/services', patterns: ['src/services/**', 'src/api/**'] },
                { name: 'src', patterns: ['src/**'], exclude: ['src/components/**', 'src/utils/**', 'src/lib/**', 'src/services/**', 'src/api/**'] }
            ]);
        });

        it('should detect Java ecosystem when pom.xml exists', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('pom.xml');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('java');
            expect(ecosystem.recommendedThresholds.total).toBe(70);
            expect(ecosystem.recommendedThresholds.changes).toBe(80);
            expect(ecosystem.suggestedGroups).toEqual([
                { name: 'main/java', patterns: ['src/main/java/**'] },
                { name: 'main/resources', patterns: ['src/main/resources/**'] },
                { name: 'test', patterns: ['src/test/**'] }
            ]);
        });

        it('should detect Java ecosystem when build.gradle exists', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('build.gradle');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('java');
        });

        it('should detect Java ecosystem when build.gradle.kts exists', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('build.gradle.kts');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('java');
        });

        it('should detect Python ecosystem when pyproject.toml exists', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('pyproject.toml');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('python');
            expect(ecosystem.recommendedThresholds.total).toBe(85);
            expect(ecosystem.recommendedThresholds.changes).toBe(90);
            expect(ecosystem.suggestedGroups).toEqual([
                { name: 'src', patterns: ['src/**', '*.py'] },
                { name: 'tests', patterns: ['tests/**', 'test/**'] },
                { name: 'package', patterns: ['**/**.py'], exclude: ['src/**', 'tests/**', 'test/**'] }
            ]);
        });

        it('should detect Python ecosystem when setup.py exists', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('setup.py');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('python');
        });

        it('should detect Python ecosystem when requirements.txt exists', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('requirements.txt');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('python');
        });

        it('should detect .NET ecosystem when .csproj files are provided', () => {
            const ecosystem = detectEcosystem(['test.csproj'], '/test/path');

            expect(ecosystem.type).toBe('dotnet');
            expect(ecosystem.recommendedThresholds.total).toBe(75);
            expect(ecosystem.recommendedThresholds.changes).toBe(80);
            expect(ecosystem.suggestedGroups).toEqual([
                { name: 'Controllers', patterns: ['**/Controllers/**'] },
                { name: 'Models', patterns: ['**/Models/**'] },
                { name: 'Services', patterns: ['**/Services/**'] },
                { name: 'Core', patterns: ['**/*.cs'], exclude: ['**/Controllers/**', '**/Models/**', '**/Services/**'] }
            ]);
        });

        it('should detect Go ecosystem when go.mod exists', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('go.mod');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('go');
            expect(ecosystem.recommendedThresholds.total).toBe(80);
            expect(ecosystem.recommendedThresholds.changes).toBe(85);
            expect(ecosystem.suggestedGroups).toEqual([
                { name: 'cmd', patterns: ['cmd/**'] },
                { name: 'internal', patterns: ['internal/**'] },
                { name: 'pkg', patterns: ['pkg/**'] },
                { name: 'root', patterns: ['*.go'] }
            ]);
        });

        it('should detect Ruby ecosystem when Gemfile exists', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().endsWith('Gemfile');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('ruby');
            expect(ecosystem.recommendedThresholds.total).toBe(80);
            expect(ecosystem.recommendedThresholds.changes).toBe(85);
            expect(ecosystem.suggestedGroups).toEqual([
                { name: 'app', patterns: ['app/**'] },
                { name: 'lib', patterns: ['lib/**'] },
                { name: 'config', patterns: ['config/**'] },
                { name: 'spec', patterns: ['spec/**'] }
            ]);
        });

        it('should default to generic ecosystem when no indicators found', () => {
            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('generic');
            expect(ecosystem.recommendedThresholds.total).toBe(50);
            expect(ecosystem.recommendedThresholds.changes).toBe(60);
            expect(ecosystem.suggestedGroups).toEqual([]);
        });

        it('should prioritize Node.js over other ecosystems', () => {
            mockFs.existsSync.mockImplementation((path) => {
                const pathStr = path.toString();
                return pathStr.endsWith('package.json') || pathStr.endsWith('pom.xml');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('node');
        });

        it('should prioritize Java over Python', () => {
            mockFs.existsSync.mockImplementation((path) => {
                const pathStr = path.toString();
                return pathStr.endsWith('pom.xml') || pathStr.endsWith('setup.py');
            });

            const ecosystem = detectEcosystem([], '/test/path');

            expect(ecosystem.type).toBe('java');
        });

        it('should use current working directory when no cwd provided', () => {
            mockFs.existsSync.mockImplementation((path) => {
                return path.toString().includes(process.cwd()) && path.toString().endsWith('package.json');
            });

            const ecosystem = detectEcosystem();

            expect(ecosystem.type).toBe('node');
            expect(mockFs.existsSync).toHaveBeenCalledWith(expect.stringContaining(process.cwd()));
        });
    });

    describe('Ecosystem-specific configurations', () => {
        it('should provide appropriate thresholds for each ecosystem', () => {
            const ecosystems = [
                { files: ['package.json'], expected: { type: 'node', total: 80, changes: 85 } },
                { files: ['pom.xml'], expected: { type: 'java', total: 70, changes: 80 } },
                { files: ['pyproject.toml'], expected: { type: 'python', total: 85, changes: 90 } },
                { files: ['*.csproj'], expected: { type: 'dotnet', total: 75, changes: 80 } },
                { files: ['go.mod'], expected: { type: 'go', total: 80, changes: 85 } },
                { files: ['Gemfile'], expected: { type: 'ruby', total: 80, changes: 85 } },
                { files: [], expected: { type: 'generic', total: 50, changes: 60 } }
            ];

            ecosystems.forEach(({ files, expected }) => {
                mockFs.existsSync.mockImplementation((path) => {
                    const pathStr = path.toString();
                    return files.some(file => 
                        file.startsWith('*') ? pathStr.includes(file.substring(1)) : pathStr.endsWith(file)
                    );
                });

                const csprojFiles = files.filter(f => f.startsWith('*')).map(f => `test${f.substring(1)}`);
                
                const ecosystem = detectEcosystem(csprojFiles, '/test/path');

                expect(ecosystem.type).toBe(expected.type);
                expect(ecosystem.recommendedThresholds.total).toBe(expected.total);
                expect(ecosystem.recommendedThresholds.changes).toBe(expected.changes);
            });
        });
    });
});
