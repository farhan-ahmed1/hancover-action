import { describe, it, expect, vi } from 'vitest';
import { log, parseGlobPatterns, isValidFilePath } from '../src/infrastructure/utils.js';

describe('utils', () => {
    describe('log', () => {
        it('should write message to stdout', () => {
            const mockWrite = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
            
            log('test message');
            
            expect(mockWrite).toHaveBeenCalledWith('test message\n');
            
            mockWrite.mockRestore();
        });

        it('should handle empty message', () => {
            const mockWrite = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
            
            log('');
            
            expect(mockWrite).toHaveBeenCalledWith('\n');
            
            mockWrite.mockRestore();
        });

        it('should handle message with special characters', () => {
            const mockWrite = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
            
            log('Message with üñïçødé and symbols @#$%');
            
            expect(mockWrite).toHaveBeenCalledWith('Message with üñïçødé and symbols @#$%\n');
            
            mockWrite.mockRestore();
        });
    });

    describe('parseGlobPatterns', () => {
        it('should return the same patterns for now', () => {
            const patterns = ['src/**/*.ts', 'test/**/*.test.ts'];
            
            const result = parseGlobPatterns(patterns);
            
            expect(result).toEqual(patterns);
        });

        it('should handle empty array', () => {
            const result = parseGlobPatterns([]);
            
            expect(result).toEqual([]);
        });

        it('should handle single pattern', () => {
            const patterns = ['*.js'];
            
            const result = parseGlobPatterns(patterns);
            
            expect(result).toEqual(patterns);
        });

        it('should handle complex patterns', () => {
            const patterns = [
                'src/**/*.{ts,js}',
                '!node_modules/**',
                'test/**/?(*.test|*.spec).ts'
            ];
            
            const result = parseGlobPatterns(patterns);
            
            expect(result).toEqual(patterns);
        });
    });

    describe('isValidFilePath', () => {
        it('should return true for now (placeholder implementation)', () => {
            const result = isValidFilePath();
            
            expect(result).toBe(true);
        });
    });
});
