import { readFileSync } from 'fs';
import { ProjectCov } from '../schema.js';
import { parseLCOV, parseLcovFile } from './lcov.js';
import { parseCobertura, parseCoberturaFile } from './cobertura.js';

/**
 * Auto-detect and parse any supported coverage format
 * Supports both LCOV (.info) and Cobertura (.xml) formats
 */
export async function parseAnyCoverage(filePath: string): Promise<ProjectCov> {
    // Auto-detect by file extension first
    if (filePath.endsWith('.info') || filePath.endsWith('.lcov')) {
        return parseLcovFile(filePath);
    }
    
    if (filePath.endsWith('.xml')) {
        return parseCoberturaFile(filePath);
    }
    
    // Fallback: sniff file content
    try {
        const head = readFileSync(filePath, 'utf8').substring(0, 200);
        
        // Check for Cobertura XML markers
        if (head.includes('<coverage') || head.includes('<!DOCTYPE coverage')) {
            return parseCoberturaFile(filePath);
        }
        
        // Check for LCOV markers
        if (head.includes('SF:') || head.includes('TN:')) {
            return parseLcovFile(filePath);
        }
        
        // Default to LCOV if uncertain
        return parseLcovFile(filePath);
    } catch (error) {
        throw new Error(`Failed to auto-detect coverage format for ${filePath}: ${error}`);
    }
}

/**
 * Parse coverage data from raw content with format detection
 */
export function parseAnyCoverageContent(content: string, hint?: 'lcov' | 'cobertura'): ProjectCov {
    if (hint === 'lcov') {
        return parseLCOV(content);
    }
    
    if (hint === 'cobertura') {
        return parseCobertura(content);
    }
    
    // Auto-detect from content
    if (content.includes('<coverage') || content.includes('<!DOCTYPE coverage')) {
        return parseCobertura(content);
    }
    
    // Default to LCOV
    return parseLCOV(content);
}

// Re-export individual parsers for direct use
export { parseLCOV, parseLcovFile } from './lcov.js';
export { parseCobertura, parseCoberturaFile } from './cobertura.js';
