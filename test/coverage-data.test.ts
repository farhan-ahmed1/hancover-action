import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as core from '@actions/core';
import * as github from '@actions/github';
import { getCoverageData, saveCoverageData } from '../src/coverage-data.js';

// Mock dependencies
vi.mock('@actions/core');
vi.mock('@actions/github');

const mockGetInput = vi.mocked(core.getInput);
const mockGetInfo = vi.mocked(core.info);
const mockGetWarning = vi.mocked(core.warning);
const mockGetError = vi.mocked(core.error);
const mockGetOctokit = vi.mocked(github.getOctokit);

describe('coverage-data', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        
        // Set up default github context mock
        Object.defineProperty(github, 'context', {
            value: {
                ref: 'refs/heads/main',
                sha: 'abc123def456'
            },
            writable: true
        });
        
        // Clear environment variables
        delete process.env.INPUT_GIST_ID;
        delete process.env.INPUT_GISTID;
        delete process.env.COVERAGE_GIST_ID;
        delete process.env.GIST_TOKEN;
    });

    afterEach(() => {
        vi.resetAllMocks();
    });

    describe('getCoverageData', () => {
        it('should return null when no gist ID provided', async () => {
            mockGetInput.mockReturnValue('');
            
            const result = await getCoverageData();
            
            expect(result).toBeNull();
            expect(mockGetInfo).toHaveBeenCalledWith('Gist ID resolution: "NOT_FOUND"');
            expect(mockGetInfo).toHaveBeenCalledWith('No gist-id provided, skipping baseline coverage fetch');
        });

        it('should return null when empty gist ID provided', async () => {
            mockGetInput.mockReturnValue('   ');
            
            const result = await getCoverageData();
            
            expect(result).toBeNull();
            expect(mockGetInfo).toHaveBeenCalledWith('No gist-id provided, skipping baseline coverage fetch');
        });

        it('should return null when no token provided', async () => {
            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id' || name === 'gistId') return 'test-gist-id';
                if (name === 'gist-token') return '';
                return '';
            });
            
            const result = await getCoverageData();
            
            expect(result).toBeNull();
            expect(mockGetWarning).toHaveBeenCalledWith('No GitHub token provided, cannot fetch from gist');
        });

        it('should fetch coverage data from gist successfully', async () => {
            const mockGist = {
                data: {
                    files: {
                        'coverage.json': {
                            content: JSON.stringify({
                                coverage: 85.5,
                                timestamp: '2024-01-01T00:00:00.000Z',
                                branch: 'main',
                                commit: 'abc123'
                            })
                        }
                    }
                }
            };

            const mockOctokit = {
                rest: {
                    gists: {
                        get: vi.fn().mockResolvedValue(mockGist)
                    }
                }
            };

            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return 'test-token';
                return '';
            });
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            const result = await getCoverageData();
            
            expect(result).toBe(85.5);
            expect(mockGetInfo).toHaveBeenCalledWith('Fetching coverage data from gist: test-gist-id');
            expect(mockGetInfo).toHaveBeenCalledWith('✅ Successfully fetched coverage: 85.5%');
            expect(mockOctokit.rest.gists.get).toHaveBeenCalledWith({
                gist_id: 'test-gist-id'
            });
        });

        it('should handle gist with no coverage file', async () => {
            const mockGist = {
                data: {
                    files: {
                        'other-file.txt': {
                            content: 'some content'
                        }
                    }
                }
            };

            const mockOctokit = {
                rest: {
                    gists: {
                        get: vi.fn().mockResolvedValue(mockGist)
                    }
                }
            };

            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return 'test-token';
                return '';
            });
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            const result = await getCoverageData();
            
            expect(result).toBeNull();
            expect(mockGetWarning).toHaveBeenCalledWith('No coverage data found in gist');
        });

        it('should handle gist API errors gracefully', async () => {
            const mockOctokit = {
                rest: {
                    gists: {
                        get: vi.fn().mockRejectedValue(new Error('API Error'))
                    }
                }
            };

            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return 'test-token';
                return '';
            });
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            const result = await getCoverageData();
            
            expect(result).toBeNull();
            expect(mockGetWarning).toHaveBeenCalledWith('No coverage data found in gist');
        });

        it('should use passed parameters over inputs', async () => {
            const mockGist = {
                data: {
                    files: {
                        'coverage.json': {
                            content: JSON.stringify({
                                coverage: 75.0,
                                timestamp: '2024-01-01T00:00:00.000Z',
                                branch: 'main',
                                commit: 'abc123'
                            })
                        }
                    }
                }
            };

            const mockOctokit = {
                rest: {
                    gists: {
                        get: vi.fn().mockResolvedValue(mockGist)
                    }
                }
            };

            mockGetInput.mockReturnValue('');
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            const result = await getCoverageData('param-gist-id', 'param-token');
            
            expect(result).toBe(75.0);
            expect(mockOctokit.rest.gists.get).toHaveBeenCalledWith({
                gist_id: 'param-gist-id'
            });
        });

        it('should check environment variables as fallback', async () => {
            process.env.INPUT_GIST_ID = 'env-gist-id';
            process.env.GIST_TOKEN = 'env-token';

            const mockGist = {
                data: {
                    files: {
                        'coverage.json': {
                            content: JSON.stringify({
                                coverage: 90.0,
                                timestamp: '2024-01-01T00:00:00.000Z',
                                branch: 'main',
                                commit: 'abc123'
                            })
                        }
                    }
                }
            };

            const mockOctokit = {
                rest: {
                    gists: {
                        get: vi.fn().mockResolvedValue(mockGist)
                    }
                }
            };

            mockGetInput.mockReturnValue('');
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            const result = await getCoverageData();
            
            expect(result).toBe(90.0);
            expect(mockOctokit.rest.gists.get).toHaveBeenCalledWith({
                gist_id: 'env-gist-id'
            });
        });

        it('should handle malformed JSON in gist', async () => {
            const mockGist = {
                data: {
                    files: {
                        'coverage.json': {
                            content: '{ invalid json'
                        }
                    }
                }
            };

            const mockOctokit = {
                rest: {
                    gists: {
                        get: vi.fn().mockResolvedValue(mockGist)
                    }
                }
            };

            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return 'test-token';
                return '';
            });
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            const result = await getCoverageData();
            
            expect(result).toBeNull();
            expect(mockGetWarning).toHaveBeenCalledWith('No coverage data found in gist');
        });
    });

    describe('saveCoverageData', () => {
        it('should skip saving when no gist ID provided', async () => {
            mockGetInput.mockReturnValue('');
            
            await saveCoverageData(85.5);
            
            expect(mockGetInfo).toHaveBeenCalledWith('No gist-id provided, skipping coverage data save');
        });

        it('should skip saving when no token provided', async () => {
            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return '';
                return '';
            });
            
            await saveCoverageData(85.5);
            
            expect(mockGetWarning).toHaveBeenCalledWith('No GitHub token provided, cannot save to gist');
        });

        it('should save coverage data successfully', async () => {
            const mockOctokit = {
                rest: {
                    gists: {
                        update: vi.fn().mockResolvedValue({})
                    }
                }
            };

            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return 'test-token';
                return '';
            });
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            await saveCoverageData(85.5);
            
            expect(mockGetInfo).toHaveBeenCalledWith('Updating coverage data in gist: test-gist-id');
            expect(mockGetInfo).toHaveBeenCalledWith('Coverage data saved: 85.5%');
            expect(mockOctokit.rest.gists.update).toHaveBeenCalledWith({
                gist_id: 'test-gist-id',
                files: {
                    'coverage.json': {
                        content: expect.stringContaining('"coverage": 85.5')
                    },
                    'coverage-badge.json': {
                        content: expect.stringContaining('"message": "85.5%"')
                    }
                }
            });
        });

        it('should handle gist update errors', async () => {
            const mockOctokit = {
                rest: {
                    gists: {
                        update: vi.fn().mockRejectedValue(new Error('Update failed'))
                    }
                }
            };

            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return 'test-token';
                return '';
            });
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            await expect(saveCoverageData(85.5)).rejects.toThrow('Update failed');
            expect(mockGetError).toHaveBeenCalledWith('Failed to update coverage in gist: Error: Update failed');
        });

        it('should use passed parameters over inputs', async () => {
            const mockOctokit = {
                rest: {
                    gists: {
                        update: vi.fn().mockResolvedValue({})
                    }
                }
            };

            mockGetInput.mockReturnValue('');
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            await saveCoverageData(75.0, 'param-gist-id', 'param-token');
            
            expect(mockOctokit.rest.gists.update).toHaveBeenCalledWith({
                gist_id: 'param-gist-id',
                files: expect.any(Object)
            });
        });

        it('should generate correct coverage badge data', async () => {
            const mockOctokit = {
                rest: {
                    gists: {
                        update: vi.fn().mockResolvedValue({})
                    }
                }
            };

            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return 'test-token';
                return '';
            });
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            await saveCoverageData(95.8);
            
            const updateCall = mockOctokit.rest.gists.update.mock.calls[0][0];
            const badgeContent = JSON.parse(updateCall.files['coverage-badge.json'].content);
            
            expect(badgeContent).toEqual({
                schemaVersion: 1,
                label: 'coverage',
                message: '95.8%',
                color: 'brightgreen'
            });
        });

        it('should generate correct color for different coverage percentages', async () => {
            const mockOctokit = {
                rest: {
                    gists: {
                        update: vi.fn().mockResolvedValue({})
                    }
                }
            };

            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return 'test-token';
                return '';
            });
            mockGetOctokit.mockReturnValue(mockOctokit as any);

            // Test different coverage levels
            const testCases = [
                { coverage: 95, expectedColor: 'brightgreen' },
                { coverage: 85, expectedColor: 'green' },
                { coverage: 75, expectedColor: 'yellowgreen' },
                { coverage: 65, expectedColor: 'yellow' },
                { coverage: 55, expectedColor: 'orange' },
                { coverage: 45, expectedColor: 'red' }
            ];

            for (const { coverage, expectedColor } of testCases) {
                mockOctokit.rest.gists.update.mockClear();
                
                await saveCoverageData(coverage);
                
                const updateCall = mockOctokit.rest.gists.update.mock.calls[0][0];
                const badgeContent = JSON.parse(updateCall.files['coverage-badge.json'].content);
                
                expect(badgeContent.color).toBe(expectedColor);
            }
        });

        it('should include correct timestamp and branch info', async () => {
            const mockOctokit = {
                rest: {
                    gists: {
                        update: vi.fn().mockResolvedValue({})
                    }
                }
            };

            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return 'test-gist-id';
                if (name === 'gist-token') return 'test-token';
                return '';
            });
            mockGetOctokit.mockReturnValue(mockOctokit as any);
            
            const startTime = Date.now();
            await saveCoverageData(85.5);
            const endTime = Date.now();
            
            const updateCall = mockOctokit.rest.gists.update.mock.calls[0][0];
            const coverageData = JSON.parse(updateCall.files['coverage.json'].content);
            
            expect(coverageData.coverage).toBe(85.5);
            expect(coverageData.branch).toBe('main');
            expect(coverageData.commit).toBe('abc123def456');
            
            const timestamp = new Date(coverageData.timestamp).getTime();
            expect(timestamp).toBeGreaterThanOrEqual(startTime);
            expect(timestamp).toBeLessThanOrEqual(endTime);
        });

        it('should handle empty string gist ID as undefined', async () => {
            mockGetInput.mockImplementation((name) => {
                if (name === 'gist-id') return '   '; // whitespace only
                return '';
            });
            
            await saveCoverageData(85.5);
            
            expect(mockGetInfo).toHaveBeenCalledWith('No gist-id provided, skipping coverage data save');
        });
    });
});
