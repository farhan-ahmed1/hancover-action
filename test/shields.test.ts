import { describe, it, expect } from 'vitest';
import { generateChangesBadge, generateBadgeUrl } from '../src/output/shields.js';

describe('shields', () => {
    describe('generateChangesBadge', () => {
        it('should generate positive change badge', () => {
            const result = generateChangesBadge(85.5, 80.0);
            
            expect(result).toBe('https://img.shields.io/badge/changes-%2B5.5%25-brightgreen');
        });

        it('should generate negative change badge', () => {
            const result = generateChangesBadge(75.2, 80.0);
            
            expect(result).toBe('https://img.shields.io/badge/changes--4.8%25-red');
        });

        it('should generate zero change badge', () => {
            const result = generateChangesBadge(80.0, 80.0);
            
            expect(result).toBe('https://img.shields.io/badge/changes-%2B0.0%25-brightgreen');
        });

        it('should handle decimal precision correctly', () => {
            const result = generateChangesBadge(82.33333, 80.11111);
            
            expect(result).toBe('https://img.shields.io/badge/changes-%2B2.2%25-brightgreen');
        });

        it('should handle large positive change', () => {
            const result = generateChangesBadge(95.0, 10.0);
            
            expect(result).toBe('https://img.shields.io/badge/changes-%2B85.0%25-brightgreen');
        });

        it('should handle large negative change', () => {
            const result = generateChangesBadge(10.0, 95.0);
            
            expect(result).toBe('https://img.shields.io/badge/changes--85.0%25-red');
        });
    });

    describe('generateBadgeUrl', () => {
        it('should generate basic badge URL', () => {
            const result = generateBadgeUrl('coverage', '85%', 'green');
            
            expect(result).toBe('https://img.shields.io/badge/coverage-85%25-green');
        });

        it('should encode special characters in label', () => {
            const result = generateBadgeUrl('test coverage', '90%', 'brightgreen');
            
            expect(result).toBe('https://img.shields.io/badge/test%20coverage-90%25-brightgreen');
        });

        it('should encode special characters in message', () => {
            const result = generateBadgeUrl('status', 'up & running', 'blue');
            
            expect(result).toBe('https://img.shields.io/badge/status-up%20%26%20running-blue');
        });

        it('should handle empty label', () => {
            const result = generateBadgeUrl('', 'value', 'gray');
            
            expect(result).toBe('https://img.shields.io/badge/-value-gray');
        });

        it('should handle empty message', () => {
            const result = generateBadgeUrl('label', '', 'red');
            
            expect(result).toBe('https://img.shields.io/badge/label--red');
        });

        it('should handle complex characters', () => {
            const result = generateBadgeUrl('test-label', '100%/95%', 'yellow');
            
            expect(result).toBe('https://img.shields.io/badge/test-label-100%25%2F95%25-yellow');
        });

        it('should handle unicode characters', () => {
            const result = generateBadgeUrl('status', '✓ passing', 'green');
            
            expect(result).toBe('https://img.shields.io/badge/status-%E2%9C%93%20passing-green');
        });
    });
});
