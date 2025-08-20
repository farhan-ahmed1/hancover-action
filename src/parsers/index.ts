import { readFileSync } from 'fs';
import { ProjectCov } from '../schema.js';
import { parseLCOV, parseLcovFile } from './lcov.js';
import { parseCobertura, parseCoberturaFile } from './cobertura.js';
import { parseClover, parseCloverFile } from './clover.js';

/**
 * Auto-detect and parse any supported coverage format
 * Supports LCOV (.info), Cobertura (.xml), and Clover (.xml) formats
 */
export async function parseAnyCoverage(filePath: string): Promise<ProjectCov> {
    // Auto-detect by file extension first
    if (filePath.endsWith('.info') || filePath.endsWith('.lcov')) {
        return parseLcovFile(filePath);
    }
    
    if (filePath.endsWith('.xml')) {
        // For XML files, we need to sniff content to distinguish between formats
        try {
            const head = readFileSync(filePath, 'utf8').substring(0, 500);
            
            // Check for Clover XML markers first (more specific)
            if (head.includes('<coverage') && (head.includes('<project') || head.includes('generator="clover'))) {
                return parseCloverFile(filePath);
            }
            
            // Check for Cobertura XML markers
            if (head.includes('<coverage') || head.includes('<!DOCTYPE coverage')) {
                return parseCoberturaFile(filePath);
            }
            
            // Default to Cobertura for XML files if uncertain
            return parseCoberturaFile(filePath);
        } catch (error) {
            throw new Error(`Failed to auto-detect XML coverage format for ${filePath}: ${error}`);
        }
    }
    
    // Fallback: sniff file content for non-standard extensions
    try {
        const head = readFileSync(filePath, 'utf8').substring(0, 500);
        
        // Check for Clover XML markers first (most specific)
        if (head.includes('<coverage') && (head.includes('<project') || head.includes('generator="clover'))) {
            return parseCloverFile(filePath);
        }
        
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
export function parseAnyCoverageContent(content: string, hint?: 'lcov' | 'cobertura' | 'clover'): ProjectCov {
    if (hint === 'lcov') {
        return parseLCOV(content);
    }
    
    if (hint === 'cobertura') {
        return parseCobertura(content);
    }
    
    if (hint === 'clover') {
        return parseClover(content);
    }
    
    // Auto-detect from content
    if (content.includes('<coverage')) {
        // Distinguish between Clover and Cobertura
        if (content.includes('<project') || content.includes('generator="clover')) {
            return parseClover(content);
        }
        // Default to Cobertura for other coverage XML
        return parseCobertura(content);
    }
    
    // Default to LCOV
    return parseLCOV(content);
}

// Re-export individual parsers for direct use
export { parseLCOV, parseLcovFile } from './lcov.js';
export { parseCobertura, parseCoberturaFile } from './cobertura.js';
export { parseClover, parseCloverFile } from './clover.js';
