import { readFileSync } from 'fs';
import { ProjectCov } from '../schema.js';
import { parseLCOV, parseLcovFile, parseLcovFileSync } from './lcov.js';
import { parseCobertura, parseCoberturaFile, parseCoberturaFileSync } from './cobertura.js';
import { parseClover, parseCloverFile, parseCloverFileSync } from './clover.js';
import { parseJaCoCo, parseJaCoCoFile, parseJaCoCoFileSync } from './jacoco.js';
import { StreamingParseOptions } from '../streaming-parser.js';
import * as core from '@actions/core';

/**
 * Auto-detect and parse any supported coverage format with enhanced performance
 * Supports LCOV (.info), Cobertura (.xml), Clover (.xml), and JaCoCo (.xml) formats
 * Features: streaming for large files, progress reporting, timeout enforcement
 */
export async function parseAnyCoverage(filePath: string, options?: StreamingParseOptions): Promise<ProjectCov> {
    // Get file stats for better processing decisions
    const stats = await import('fs/promises').then(fs => fs.stat(filePath));
    const fileSizeBytes = stats.size;
    
    core.info(`Auto-detecting coverage format for: ${filePath} (${formatBytes(fileSizeBytes)})`);
    
    // Auto-detect by file extension first
    if (filePath.endsWith('.info') || filePath.endsWith('.lcov')) {
        return parseLcovFile(filePath, options?.timeoutMs);
    }
    
    if (filePath.endsWith('.xml')) {
        // For XML files, we need to sniff content to distinguish between formats
        try {
            const head = readFileSync(filePath, 'utf8').substring(0, 500);
            
            // Check for JaCoCo XML markers first (most specific)
            if (head.includes('<report') && (head.includes('<!DOCTYPE report PUBLIC "-//JACOCO//') || head.includes('<package') && head.includes('<counter type='))) {
                return parseJaCoCoFile(filePath, options);
            }
            
            // Check for Clover XML markers (more specific than Cobertura)
            if (head.includes('<coverage') && (head.includes('<project') || head.includes('generator="clover'))) {
                return parseCloverFile(filePath, options);
            }
            
            // Check for Cobertura XML markers
            if (head.includes('<coverage') || head.includes('<!DOCTYPE coverage')) {
                return parseCoberturaFile(filePath, options);
            }
            
            // Default to Cobertura for XML files if uncertain
            return parseCoberturaFile(filePath, options);
        } catch (error) {
            throw new Error(`Failed to auto-detect XML coverage format for ${filePath}: ${error}`);
        }
    }
    
    // Fallback: sniff file content for non-standard extensions
    try {
        const head = readFileSync(filePath, 'utf8').substring(0, 500);
        
        // Check for JaCoCo XML markers first (most specific)
        if (head.includes('<report') && (head.includes('<!DOCTYPE report PUBLIC "-//JACOCO//') || head.includes('<package') && head.includes('<counter type='))) {
            return parseJaCoCoFile(filePath, options);
        }
        
        // Check for Clover XML markers (most specific)
        if (head.includes('<coverage') && (head.includes('<project') || head.includes('generator="clover'))) {
            return parseCloverFile(filePath, options);
        }
        
        // Check for Cobertura XML markers
        if (head.includes('<coverage') || head.includes('<!DOCTYPE coverage')) {
            return parseCoberturaFile(filePath, options);
        }
        
        // Check for LCOV markers
        if (head.includes('SF:') || head.includes('TN:')) {
            return parseLcovFile(filePath, options?.timeoutMs);
        }
        
        // Default to LCOV if uncertain
        return parseLcovFile(filePath, options?.timeoutMs);
    } catch (error) {
        throw new Error(`Failed to auto-detect coverage format for ${filePath}: ${error}`);
    }
}

/**
 * Parse coverage data from raw content with format detection
 */
export function parseAnyCoverageContent(content: string, hint?: 'lcov' | 'cobertura' | 'clover' | 'jacoco'): ProjectCov {
    if (hint === 'lcov') {
        return parseLCOV(content);
    }
    
    if (hint === 'cobertura') {
        return parseCobertura(content);
    }
    
    if (hint === 'clover') {
        return parseClover(content);
    }
    
    if (hint === 'jacoco') {
        return parseJaCoCo(content);
    }
    
    // Auto-detect from content
    if (content.includes('<report') && (content.includes('<!DOCTYPE report PUBLIC "-//JACOCO//') || content.includes('<package') && content.includes('<counter type='))) {
        return parseJaCoCo(content);
    }
    
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

/**
 * Format bytes for human-readable display
 */
function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Re-export individual parsers for direct use
export { parseLCOV, parseLcovFile, parseLcovFileSync } from './lcov.js';
export { parseCobertura, parseCoberturaFile, parseCoberturaFileSync } from './cobertura.js';
export { parseClover, parseCloverFile, parseCloverFileSync } from './clover.js';
export { parseJaCoCo, parseJaCoCoFile, parseJaCoCoFileSync } from './jacoco.js';