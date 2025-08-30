import { describe, it, expect } from 'vitest';
import { 
    generateBadgeUrl, 
    generateCoverageBadge, 
    generateBuildBadge, 
    generateDeltaBadge, 
    createShieldsBadge, 
    getColorForPercentage, 
    getHealthIcon 
} from '../../src/output/badges.js';

describe('badges', () => {
    describe('generateBadgeUrl', () => {
        it('should generate badge URL with default color', () => {
            const result = generateBadgeUrl('test', 'value');
            expect(result).toBe('https://img.shields.io/badge/test-value-blue');
        });

        it('should generate badge URL with custom color', () => {
            const result = generateBadgeUrl('coverage', '85%', 'green');
            expect(result).toBe('https://img.shields.io/badge/coverage-85%25-green');
        });

        it('should encode special characters', () => {
            const result = generateBadgeUrl('test coverage', '90% passed', 'brightgreen');
            expect(result).toBe('https://img.shields.io/badge/test%20coverage-90%25%20passed-brightgreen');
        });

        it('should handle empty strings', () => {
            const result = generateBadgeUrl('', '', 'gray');
            expect(result).toBe('https://img.shields.io/badge/--gray');
        });
    });

    describe('generateCoverageBadge', () => {
        it('should generate coverage badge with high percentage', () => {
            const result = generateCoverageBadge(95.5);
            expect(result).toBe('https://img.shields.io/badge/coverage-95.5%25-brightgreen');
        });

        it('should generate coverage badge with medium percentage', () => {
            const result = generateCoverageBadge(75.2);
            expect(result).toBe('https://img.shields.io/badge/coverage-75.2%25-yellowgreen');
        });

        it('should generate coverage badge with low percentage', () => {
            const result = generateCoverageBadge(45.8);
            expect(result).toBe('https://img.shields.io/badge/coverage-45.8%25-red');
        });

        it('should handle zero coverage', () => {
            const result = generateCoverageBadge(0);
            expect(result).toBe('https://img.shields.io/badge/coverage-0.0%25-red');
        });

        it('should handle 100% coverage', () => {
            const result = generateCoverageBadge(100);
            expect(result).toBe('https://img.shields.io/badge/coverage-100.0%25-brightgreen');
        });
    });

    describe('generateBuildBadge', () => {
        it('should generate passing build badge', () => {
            const result = generateBuildBadge('passing');
            expect(result).toBe('https://img.shields.io/badge/build-passing-brightgreen');
        });

        it('should generate failing build badge', () => {
            const result = generateBuildBadge('failing');
            expect(result).toBe('https://img.shields.io/badge/build-failing-red');
        });

        it('should handle other status strings', () => {
            const result = generateBuildBadge('unknown');
            expect(result).toBe('https://img.shields.io/badge/build-unknown-red');
        });

        it('should handle empty status', () => {
            const result = generateBuildBadge('');
            expect(result).toBe('https://img.shields.io/badge/build--red');
        });
    });

    describe('generateDeltaBadge', () => {
        it('should generate positive delta badge', () => {
            const result = generateDeltaBadge(5.3);
            expect(result).toBe('https://img.shields.io/badge/%CE%94%20coverage-%2B5.3%25-brightgreen');
        });

        it('should generate negative delta badge', () => {
            const result = generateDeltaBadge(-3.7);
            expect(result).toBe('https://img.shields.io/badge/%CE%94%20coverage--3.7%25-red');
        });

        it('should generate zero delta badge', () => {
            const result = generateDeltaBadge(0);
            expect(result).toBe('https://img.shields.io/badge/%CE%94%20coverage-%2B0.0%25-brightgreen');
        });

        it('should handle large positive delta', () => {
            const result = generateDeltaBadge(25.8);
            expect(result).toBe('https://img.shields.io/badge/%CE%94%20coverage-%2B25.8%25-brightgreen');
        });

        it('should handle large negative delta', () => {
            const result = generateDeltaBadge(-15.2);
            expect(result).toBe('https://img.shields.io/badge/%CE%94%20coverage--15.2%25-red');
        });
    });

    describe('createShieldsBadge', () => {
        it('should create shields badge with encoded values', () => {
            const result = createShieldsBadge('test', 'value', 'blue');
            expect(result).toBe('https://img.shields.io/badge/test-value-blue');
        });

        it('should encode special characters in label and message', () => {
            const result = createShieldsBadge('test label', 'value & more', 'green');
            expect(result).toBe('https://img.shields.io/badge/test%20label-value%20%26%20more-green');
        });

        it('should handle unicode characters', () => {
            const result = createShieldsBadge('status', '✓ passing', 'brightgreen');
            expect(result).toBe('https://img.shields.io/badge/status-%E2%9C%93%20passing-brightgreen');
        });
    });

    describe('getColorForPercentage', () => {
        it('should return brightgreen for 90% and above', () => {
            expect(getColorForPercentage(90)).toBe('brightgreen');
            expect(getColorForPercentage(95)).toBe('brightgreen');
            expect(getColorForPercentage(100)).toBe('brightgreen');
        });

        it('should return green for 80-89%', () => {
            expect(getColorForPercentage(80)).toBe('green');
            expect(getColorForPercentage(85)).toBe('green');
            expect(getColorForPercentage(89.9)).toBe('green');
        });

        it('should return yellowgreen for 70-79%', () => {
            expect(getColorForPercentage(70)).toBe('yellowgreen');
            expect(getColorForPercentage(75)).toBe('yellowgreen');
            expect(getColorForPercentage(79.9)).toBe('yellowgreen');
        });

        it('should return yellow for 60-69%', () => {
            expect(getColorForPercentage(60)).toBe('yellow');
            expect(getColorForPercentage(65)).toBe('yellow');
            expect(getColorForPercentage(69.9)).toBe('yellow');
        });

        it('should return orange for 50-59%', () => {
            expect(getColorForPercentage(50)).toBe('orange');
            expect(getColorForPercentage(55)).toBe('orange');
            expect(getColorForPercentage(59.9)).toBe('orange');
        });

        it('should return red for below 50%', () => {
            expect(getColorForPercentage(0)).toBe('red');
            expect(getColorForPercentage(25)).toBe('red');
            expect(getColorForPercentage(49.9)).toBe('red');
        });
    });

    describe('getHealthIcon', () => {
        it('should return checkmark for percentage at or above default threshold', () => {
            expect(getHealthIcon(50)).toBe('✅');
            expect(getHealthIcon(75)).toBe('✅');
            expect(getHealthIcon(100)).toBe('✅');
        });

        it('should return X mark for percentage below default threshold', () => {
            expect(getHealthIcon(0)).toBe('❌');
            expect(getHealthIcon(25)).toBe('❌');
            expect(getHealthIcon(49.9)).toBe('❌');
        });

        it('should use custom threshold', () => {
            expect(getHealthIcon(70, 80)).toBe('❌');
            expect(getHealthIcon(80, 80)).toBe('✅');
            expect(getHealthIcon(90, 80)).toBe('✅');
        });

        it('should handle zero threshold', () => {
            expect(getHealthIcon(0, 0)).toBe('✅');
            expect(getHealthIcon(10, 0)).toBe('✅');
        });

        it('should handle high threshold', () => {
            expect(getHealthIcon(95, 99)).toBe('❌');
            expect(getHealthIcon(99, 99)).toBe('✅');
            expect(getHealthIcon(100, 99)).toBe('✅');
        });
    });
});
