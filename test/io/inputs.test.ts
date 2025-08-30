import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readInputs } from '../../src/io/inputs.js';

describe('inputs', () => {
    const originalEnv = process.env;

    beforeEach(() => {
        // Clear all environment variables
        vi.clearAllMocks();
        process.env = {};
    });

    afterEach(() => {
        process.env = originalEnv;
    });

    describe('readInputs', () => {
        it('should read inputs with default values', () => {
            process.env = {
                'INPUT_FILES': 'coverage.xml\nlcov.info',
            };

            const result = readInputs();

            expect(result).toEqual({
                files: ['coverage.xml', 'lcov.info'],
                baseRef: undefined,
                thresholds: undefined,
                warnOnly: false,
                commentMode: 'update',
                groups: undefined,
                maxBytesPerFile: 52428800,
                maxTotalBytes: 209715200,
                timeoutSeconds: 120,
                strict: false,
                baselineFiles: undefined,
                minThreshold: 50,
                coverageDataPath: '.github/coverage-data.json'
            });
        });

        it('should handle all inputs with custom values', () => {
            process.env = {
                'INPUT_FILES': 'test-coverage.xml',
                'INPUT_BASE-REF': 'main',
                'INPUT_THRESHOLDS': '{"lines": 80}',
                'INPUT_WARN-ONLY': 'true',
                'INPUT_COMMENT-MODE': 'new',
                'INPUT_GROUPS': '[{"name": "frontend", "paths": ["src/frontend/**"]}]',
                'INPUT_MAX-BYTES-PER-FILE': '1000000',
                'INPUT_MAX-TOTAL-BYTES': '5000000',
                'INPUT_TIMEOUT-SECONDS': '60',
                'INPUT_STRICT': 'true',
                'INPUT_BASELINE-FILES': 'baseline1.xml\nbaseline2.xml',
                'INPUT_MIN-THRESHOLD': '75'
            };

            const result = readInputs();

            expect(result).toEqual({
                files: ['test-coverage.xml'],
                baseRef: 'main',
                thresholds: '{"lines": 80}',
                warnOnly: true,
                commentMode: 'new',
                groups: [{'name': 'frontend', 'paths': ['src/frontend/**']}],
                maxBytesPerFile: 1000000,
                maxTotalBytes: 5000000,
                timeoutSeconds: 60,
                strict: true,
                baselineFiles: ['baseline1.xml', 'baseline2.xml'],
                minThreshold: 75,
                coverageDataPath: '.github/coverage-data.json'
            });
        });

        it('should handle files input with only whitespace', () => {
            process.env = {
                'INPUT_FILES': 'file1.xml\n  \n  \nfile2.xml',  // Valid files with empty lines
            };

            const result = readInputs();

            expect(result.files).toEqual(['file1.xml', 'file2.xml']);
        });

        it('should handle whitespace in files input', () => {
            process.env = {
                'INPUT_FILES': '  coverage.xml  \n  \n  lcov.info  ',
            };

            const result = readInputs();

            expect(result.files).toEqual(['coverage.xml', 'lcov.info']);
        });

        it('should handle invalid YAML groups gracefully', () => {
            process.env = {
                'INPUT_FILES': 'coverage.xml',
                'INPUT_GROUPS': 'invalid: yaml: [',
            };

            const result = readInputs();

            expect(result.groups).toBeUndefined();
        });

        it('should handle non-array YAML groups', () => {
            process.env = {
                'INPUT_FILES': 'coverage.xml',
                'INPUT_GROUPS': 'name: "test"',
            };

            const result = readInputs();

            expect(result.groups).toBeUndefined();
        });

        it('should handle missing baseline files', () => {
            process.env = {
                'INPUT_FILES': 'coverage.xml',
            };

            const result = readInputs();

            expect(result.baselineFiles).toBeUndefined();
        });

        it('should parse baseline files correctly', () => {
            process.env = {
                'INPUT_FILES': 'coverage.xml',
                'INPUT_BASELINE-FILES': '  baseline1.xml  \n  baseline2.xml  \n  ',
            };

            const result = readInputs();

            expect(result.baselineFiles).toEqual(['baseline1.xml', 'baseline2.xml']);
        });

        it('should handle boolean inputs as strings', () => {
            process.env = {
                'INPUT_FILES': 'coverage.xml',
                'INPUT_WARN-ONLY': 'false',
                'INPUT_STRICT': 'false',
            };

            const result = readInputs();

            expect(result.warnOnly).toBe(false);
            expect(result.strict).toBe(false);
        });

        it('should handle numeric inputs', () => {
            process.env = {
                'INPUT_FILES': 'coverage.xml',
                'INPUT_MAX-BYTES-PER-FILE': '123456',
                'INPUT_MAX-TOTAL-BYTES': '987654',
                'INPUT_TIMEOUT-SECONDS': '30',
                'INPUT_MIN-THRESHOLD': '90',
            };

            const result = readInputs();

            expect(result.maxBytesPerFile).toBe(123456);
            expect(result.maxTotalBytes).toBe(987654);
            expect(result.timeoutSeconds).toBe(30);
            expect(result.minThreshold).toBe(90);
        });
    });
});
