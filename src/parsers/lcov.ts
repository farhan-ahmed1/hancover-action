import { FileCov, ProjectCov } from '../processing/schema.js';
import { enforceFileSizeLimits } from '../infrastructure/fs-limits.js';
import { withFileTimeout, globalTimeoutManager } from '../infrastructure/timeout-utils.js';
import { globalProgressReporter } from '../infrastructure/progress-reporter.js';
import * as core from '@actions/core';

/**
 * Parse LCOV format coverage data
 * 
 * LCOV format specification (http://ltp.sourceforge.net/coverage/lcov/geninfo.1.php):
 * SF:<path>                     - Source file path
 * FN:<line>,<function>          - Function definition (line number, function name)
 * FNDA:<hits>,<function>        - Function hit data (execution count, function name)
 * FNF:<functions_found>         - Number of functions found
 * FNH:<functions_hit>           - Number of functions hit
 * BRDA:<line>,<block>,<branch>,<taken> - Branch coverage data
 * BRF:<branches_found>          - Number of branches found  
 * BRH:<branches_hit>            - Number of branches hit
 * DA:<line>,<hits>              - Line coverage data (line number, execution count)
 * LF:<lines_found>              - Number of instrumented lines
 * LH:<lines_hit>                - Number of lines with non-zero execution count
 * end_of_record                 - End of record marker
 * 
 * Security measures:
 * - Input validation and sanitization
 * - File size limits enforcement
 * - Path sanitization to prevent directory traversal
 * - Safe numeric parsing with bounds checking
 * - Memory usage protection against malformed data
 */
export function parseLCOV(data: string): ProjectCov {
    try {
        // Security: Basic input validation first
        if (typeof data !== 'string') {
            throw new Error('LCOV data must be a string');
        }
        
        // Security: Enforce file size limits to prevent memory exhaustion
        const dataSize = Buffer.byteLength(data, 'utf8');
        enforceFileSizeLimits(dataSize);
        
        const files: FileCov[] = [];
        let currentFile: Partial<FileCov> | null = null;
        
        // Track function definitions and hits per file
        const functionDefs = new Map<string, Set<string>>(); // path -> function names
        const functionHits = new Map<string, Map<string, number>>(); // path -> (function name -> execution count)
        
        // Track branch data per file
        const branchData = new Map<string, Array<{ line: number; block: number; branch: number; taken: number | null }>>(); 
        
        // Security: Limit line processing to prevent excessive memory usage
        const lines = data.split('\n');
        if (lines.length > 1000000) { // 1M lines limit
            throw new Error('LCOV file has excessive number of lines (> 1M), which may indicate malformed data');
        }
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const trimmed = line.trim();
            
            // Skip empty lines and comments
            if (!trimmed || trimmed.startsWith('#')) {
                continue;
            }
            
            try {
                if (trimmed.startsWith('SF:')) {
                    // Start of file - finalize previous file if exists
                    if (currentFile && currentFile.path) {
                        finalizeCoverageFile(currentFile, functionDefs, functionHits, branchData, files);
                    }
                    
                    // Extract and sanitize file path
                    const filePath = trimmed.substring(3).trim();
                    const normalizedPath = sanitizeFilePath(filePath);
                    
                    currentFile = {
                        path: normalizedPath,
                        lines: { covered: 0, total: 0 },
                        branches: { covered: 0, total: 0 },
                        functions: { covered: 0, total: 0 },
                        coveredLineNumbers: new Set<number>()
                    };
                    
                } else if (trimmed.startsWith('DA:') && currentFile) {
                    // Line coverage: DA:<line>,<hits>
                    const colonIndex = trimmed.indexOf(':', 2);
                    if (colonIndex > 0) {
                        const dataStr = trimmed.substring(colonIndex + 1);
                        const commaIndex = dataStr.indexOf(',');
                        
                        if (commaIndex > 0) {
                            const lineStr = dataStr.substring(0, commaIndex);
                            const hitsStr = dataStr.substring(commaIndex + 1);
                            
                            const lineNumber = parseIntSafe(lineStr);
                            const hits = parseIntSafe(hitsStr);
                            
                            if (lineNumber !== null && hits !== null && lineNumber > 0) {
                                currentFile.lines!.total++;
                                if (hits > 0) {
                                    currentFile.lines!.covered++;
                                    currentFile.coveredLineNumbers!.add(lineNumber);
                                }
                            }
                        }
                    }
                    
                } else if (trimmed.startsWith('FN:') && currentFile) {
                    // Function definition: FN:<start_line>,<function_name>
                    const colonIndex = trimmed.indexOf(':', 2);
                    if (colonIndex > 0) {
                        const dataStr = trimmed.substring(colonIndex + 1);
                        const commaIndex = dataStr.indexOf(',');
                        
                        if (commaIndex > 0) {
                            const lineStr = dataStr.substring(0, commaIndex);
                            const functionName = dataStr.substring(commaIndex + 1).trim();
                            
                            const lineNumber = parseIntSafe(lineStr);
                            if (lineNumber !== null && lineNumber > 0 && functionName) {
                                const filePath = currentFile.path!;
                                
                                if (!functionDefs.has(filePath)) {
                                    functionDefs.set(filePath, new Set());
                                }
                                functionDefs.get(filePath)!.add(functionName);
                            }
                        }
                    }
                    
                } else if (trimmed.startsWith('FNDA:') && currentFile) {
                    // Function hit data: FNDA:<hits>,<function_name>
                    const colonIndex = trimmed.indexOf(':', 4);
                    if (colonIndex > 0) {
                        const dataStr = trimmed.substring(colonIndex + 1);
                        const commaIndex = dataStr.indexOf(',');
                        
                        if (commaIndex > 0) {
                            const hitsStr = dataStr.substring(0, commaIndex);
                            const functionName = dataStr.substring(commaIndex + 1).trim();
                            
                            const hits = parseIntSafe(hitsStr);
                            if (hits !== null && functionName) {
                                const filePath = currentFile.path!;
                                if (!functionHits.has(filePath)) {
                                    functionHits.set(filePath, new Map());
                                }
                                const fileHits = functionHits.get(filePath)!;
                                // Take the maximum hits across multiple FNDA records for the same function
                                const currentHits = fileHits.get(functionName) || 0;
                                fileHits.set(functionName, Math.max(currentHits, hits));
                            }
                        }
                    }
                    
                } else if (trimmed.startsWith('BRDA:') && currentFile) {
                    // Branch coverage: BRDA:<line>,<block>,<branch>,<taken>
                    const colonIndex = trimmed.indexOf(':', 4);
                    if (colonIndex > 0) {
                        const dataStr = trimmed.substring(colonIndex + 1);
                        const parts = dataStr.split(',');
                        
                        if (parts.length >= 4) {
                            const lineNumber = parseIntSafe(parts[0]);
                            const block = parseIntSafe(parts[1]);
                            const branch = parseIntSafe(parts[2]);
                            const takenStr = parts[3].trim();
                            
                            if (lineNumber !== null && block !== null && branch !== null && lineNumber > 0) {
                                const taken = takenStr === '-' ? null : parseIntSafe(takenStr);
                                
                                const filePath = currentFile.path!;
                                if (!branchData.has(filePath)) {
                                    branchData.set(filePath, []);
                                }
                                branchData.get(filePath)!.push({ line: lineNumber, block, branch, taken });
                            }
                        }
                    }
                    
                } else if (trimmed.startsWith('LF:') && currentFile) {
                    // Lines found - parse for potential validation (currently unused but could be used for validation)
                    parseIntSafe(trimmed.substring(3).trim());
                    
                } else if (trimmed.startsWith('LH:') && currentFile) {
                    // Lines hit - parse for potential validation (currently unused but could be used for validation)
                    parseIntSafe(trimmed.substring(3).trim());
                    
                } else if (trimmed.startsWith('FNF:') && currentFile) {
                    // Functions found - parse for potential validation (currently unused but could be used for validation)
                    parseIntSafe(trimmed.substring(4).trim());
                    
                } else if (trimmed.startsWith('FNH:') && currentFile) {
                    // Functions hit - parse for potential validation (currently unused but could be used for validation)
                    parseIntSafe(trimmed.substring(4).trim());
                    
                } else if (trimmed.startsWith('BRF:') && currentFile) {
                    // Branches found - parse for potential validation (currently unused but could be used for validation)
                    parseIntSafe(trimmed.substring(4).trim());
                    
                } else if (trimmed.startsWith('BRH:') && currentFile) {
                    // Branches hit - parse for potential validation (currently unused but could be used for validation)
                    parseIntSafe(trimmed.substring(4).trim());
                    
                } else if (trimmed === 'end_of_record') {
                    // End of current file record
                    if (currentFile && currentFile.path) {
                        finalizeCoverageFile(currentFile, functionDefs, functionHits, branchData, files);
                    }
                    currentFile = null;
                }
                // Skip unknown record types silently for forward compatibility
                
            } catch {
                // Skip malformed records silently to maintain robustness while processing
                continue;
            }
        }
        
        // Handle case where file doesn't end with end_of_record
        if (currentFile && currentFile.path) {
            finalizeCoverageFile(currentFile, functionDefs, functionHits, branchData, files);
        }
        
        // Compute project totals
        const totals = {
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        };
        
        for (const file of files) {
            totals.lines.covered += file.lines.covered;
            totals.lines.total += file.lines.total;
            totals.branches.covered += file.branches.covered;
            totals.branches.total += file.branches.total;
            totals.functions.covered += file.functions.covered;
            totals.functions.total += file.functions.total;
        }
        
        return { files, totals };
        
    } catch (error) {
        if (error instanceof Error) {
            throw new Error(`Failed to parse LCOV data: ${error.message}`);
        }
        throw new Error('Failed to parse LCOV data: Unknown error');
    }
}

function finalizeCoverageFile(
    currentFile: Partial<FileCov>, 
    functionDefs: Map<string, Set<string>>, 
    functionHits: Map<string, Map<string, number>>,
    branchData: Map<string, Array<{ line: number; block: number; branch: number; taken: number | null }>>,
    files: FileCov[]
): void {
    const filePath = currentFile.path!;
    
    // Calculate function coverage
    const definedFunctions = functionDefs.get(filePath) || new Set();
    const hitData = functionHits.get(filePath) || new Map();
    
    currentFile.functions = { covered: 0, total: definedFunctions.size };
    
    for (const funcName of definedFunctions) {
        const hits = hitData.get(funcName) || 0;
        if (hits > 0) {
            currentFile.functions.covered++;
        }
    }
    
    // If no functions were defined via FN: records, but we have FNDA: records,
    // use the FNDA records as the source of truth
    if (definedFunctions.size === 0 && hitData.size > 0) {
        currentFile.functions.total = hitData.size;
        for (const [, hits] of hitData) {
            if (hits > 0) {
                currentFile.functions.covered++;
            }
        }
    }
    
    // Calculate branch coverage from BRDA records
    const branches = branchData.get(filePath) || [];
    currentFile.branches = { covered: 0, total: 0 };
    
    for (const branch of branches) {
        currentFile.branches.total++;
        if (branch.taken !== null && branch.taken > 0) {
            currentFile.branches.covered++;
        }
    }
    
    files.push(currentFile as FileCov);
}

/**
 * Read LCOV file from disk and parse it with streaming support
 */
export async function parseLcovFile(filePath: string, timeoutMs?: number): Promise<ProjectCov> {
    try {
        // Get file stats for progress reporting and timeout calculation
        const stats = await import('fs/promises').then(fs => fs.stat(filePath));
        const fileSizeBytes = stats.size;
        
        core.info(`Processing LCOV file: ${filePath} (${formatBytes(fileSizeBytes)})`);
        
        // Security: Check file size before processing
        enforceFileSizeLimits(fileSizeBytes);
        
        // Calculate timeout based on file size
        const calculatedTimeoutMs = timeoutMs ?? globalTimeoutManager.calculateTimeout(fileSizeBytes);
        
        // Progress reporting for large files
        let lastProgress = 0;
        const reportProgress = (bytesRead: number) => {
            const percentage = (bytesRead / fileSizeBytes) * 100;
            if (percentage - lastProgress >= 10 || percentage === 100) { // Report every 10%
                globalProgressReporter.report(
                    'Reading LCOV file',
                    percentage,
                    ` - ${formatBytes(bytesRead)}/${formatBytes(fileSizeBytes)}`
                );
                lastProgress = percentage;
            }
        };

        // Use async file reading with timeout for large files
        const data = await withFileTimeout(
            readFileWithProgress(filePath, reportProgress),
            filePath,
            fileSizeBytes,
            calculatedTimeoutMs
        );
        
        globalProgressReporter.report('Parsing LCOV content', 0);
        const result = parseLCOV(data);
        globalProgressReporter.report('LCOV parsing complete', 100);
        
        return result;
    } catch (error) {
        throw new Error(`Failed to read LCOV file ${filePath}: ${error}`);
    }
}

/**
 * Read file with progress reporting
 */
// eslint-disable-next-line no-unused-vars
async function readFileWithProgress(filePath: string, onProgress: (bytesRead: number) => void): Promise<string> {
    const fs = await import('fs');
    const { createReadStream } = fs;
    
    return new Promise((resolve, reject) => {
        let content = '';
        let bytesRead = 0;
        
        const stream = createReadStream(filePath, { encoding: 'utf8' });
        
        stream.on('data', (chunk: string | Buffer) => {
            const chunkStr = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
            content += chunkStr;
            bytesRead += Buffer.byteLength(chunkStr, 'utf8');
            onProgress(bytesRead);
        });
        
        stream.on('end', () => {
            resolve(content);
        });
        
        stream.on('error', (error) => {
            reject(error);
        });
    });
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

// Helper functions

/**
 * Safely parse integer from string, return null if invalid
 * Includes bounds checking to prevent integer overflow issues
 * For LCOV, we only accept non-negative integers (hit counts cannot be negative)
 */
function parseIntSafe(value: any): number | null {
    if (value === undefined || value === null) return null;
    
    const stringValue = String(value).trim();
    
    // Check if it's a valid non-negative integer string (only digits)
    if (!/^\d+$/.test(stringValue)) {
        return null;
    }
    
    const parsed = parseInt(stringValue, 10);
    if (isNaN(parsed)) return null;
    
    // Security: Bounds checking to prevent integer overflow
    // LCOV hit counts should be non-negative and within safe integer range
    if (parsed < 0 || parsed > Number.MAX_SAFE_INTEGER) return null;
    
    return parsed;
}

/**
 * Sanitize file path to prevent directory traversal attacks
 */
function sanitizeFilePath(filePath: string): string {
    if (!filePath || typeof filePath !== 'string') {
        return '';
    }
    
    // Basic normalization - remove excessive slashes and resolve relative paths
    let normalized = filePath.replace(/[/\\]+/g, '/');
    
    // Split path into segments and sanitize each segment
    const segments = normalized.split('/');
    const cleanSegments: string[] = [];
    
    for (const segment of segments) {
        // Skip empty segments, current directory references, and parent directory references
        if (!segment || segment === '.' || segment === '..') {
            continue;
        }
        
        // Additional security: limit segment length and validate characters
        if (segment.length > 255) {
            continue; // Skip overly long segments
        }
        
        // Remove potentially dangerous characters but keep common filename chars
        const cleanSegment = segment.replace(/[<>:"|?*\x00-\x1f]/g, '');
        
        if (cleanSegment && cleanSegment.length > 0) {
            cleanSegments.push(cleanSegment);
        }
    }
    
    return cleanSegments.join('/');
}