import { XMLParser } from 'fast-xml-parser';
import { readFileSync } from 'fs';
import { FileCov, ProjectCov } from '../schema.js';
import { validateXmlSecurity } from '../fs-limits.js';

/**
 * Parse Clover XML coverage format
 * 
 * Clover XML structure:
 * <coverage>
 *   <project>
 *     <package name="package.name">
 *       <file name="file.ext" path="/path/to/file.ext">
 *         <line num="1" type="stmt" count="5"/>
 *         <line num="2" type="cond" count="2" truecount="1" falsecount="1"/>
 *         <line num="3" type="method" count="1"/>
 *       </file>
 *     </package>
 *   </project>
 * </coverage>
 * 
 * Security measures:
 * - XML security validation (DTD/Entity protection)
 * - Safe XML parser configuration  
 * - Input validation and sanitization
 * - Bounded parsing (nested structure limits handled by security validator)
 */
export function parseClover(xmlContent: string): ProjectCov {
    try {
        // Security validation before parsing - protects against XXE, XML bombs, etc.
        validateXmlSecurity(xmlContent);
        
        const parser = new XMLParser({
            ignoreAttributes: false,
            attributeNamePrefix: '@_',
            // Security: Disable DTD processing and external entity loading to prevent XXE attacks
            processEntities: false,
            ignoreDeclaration: true,
            trimValues: true,
            // Additional security measures
            allowBooleanAttributes: false,
            parseTagValue: false, // Prevent script injection in tag values
            parseAttributeValue: false // Keep attribute values as strings
        });
        
        const result = parser.parse(xmlContent);
        const coverage = result.coverage;
        
        if (!coverage) {
            return createEmptyProjectCov();
        }

        // Handle different Clover XML structures
        let project = coverage.project;
        if (!project) {
            return createEmptyProjectCov();
        }

        const filesMap: Record<string, FileCov> = {};

        // Handle packages - can be single object or array
        let packages = [];
        if (project.package) {
            packages = Array.isArray(project.package) 
                ? project.package 
                : [project.package];
        } else if (project.packages?.package) {
            // Some Clover variants wrap packages in a <packages> element
            packages = Array.isArray(project.packages.package) 
                ? project.packages.package 
                : [project.packages.package];
        }

        for (const pkg of packages) {
            if (!pkg) continue;
            
            // Handle files - can be single object or array
            let files = [];
            if (pkg.file) {
                files = Array.isArray(pkg.file) ? pkg.file : [pkg.file];
            }

            for (const file of files) {
                if (!file || !file['@_name']) continue;
                
                // Get file path - prefer 'path' attribute, fallback to 'name'
                const filePath = file['@_path'] || file['@_name'];
                if (!filePath) continue;

                // Validate file path to prevent directory traversal
                const normalizedPath = sanitizeFilePath(filePath);
                
                // Get or create file entry
                if (!filesMap[normalizedPath]) {
                    filesMap[normalizedPath] = {
                        path: normalizedPath,
                        lines: { covered: 0, total: 0 },
                        branches: { covered: 0, total: 0 },
                        functions: { covered: 0, total: 0 },
                        coveredLineNumbers: new Set<number>(),
                        package: pkg['@_name'] || undefined
                    };
                }
                
                const fileCov = filesMap[normalizedPath];

                // Parse line coverage
                if (file.line) {
                    const lines = Array.isArray(file.line) ? file.line : [file.line];
                    
                    for (const line of lines) {
                        if (!line || !line['@_num'] || line['@_count'] === undefined) continue;
                        
                        const lineNumber = parseIntSafe(line['@_num']);
                        const count = parseIntSafe(line['@_count']);
                        const lineType = line['@_type']?.toLowerCase();
                        
                        if (lineNumber === null || count === null) continue;
                        
                        // Process different line types
                        switch (lineType) {
                        case 'stmt':
                        case 'statement':
                            // Statement/line coverage
                            fileCov.lines.total++;
                            if (count > 0) {
                                fileCov.lines.covered++;
                                fileCov.coveredLineNumbers.add(lineNumber);
                            }
                            break;
                                
                        case 'cond':
                        case 'conditional':
                            // Branch coverage - Clover uses truecount/falsecount
                            const trueCount = parseIntSafe(line['@_truecount']) || 0;
                            const falseCount = parseIntSafe(line['@_falsecount']) || 0;
                                
                            // Each conditional can have 2 branches (true/false)
                            fileCov.branches.total += 2;
                            if (trueCount > 0) fileCov.branches.covered++;
                            if (falseCount > 0) fileCov.branches.covered++;
                                
                            // If the line was executed, count as covered line too
                            if (count > 0) {
                                fileCov.lines.total++;
                                fileCov.lines.covered++;
                                fileCov.coveredLineNumbers.add(lineNumber);
                            }
                            break;
                                
                        case 'method':
                        case 'function':
                            // Function/method coverage
                            fileCov.functions.total++;
                            if (count > 0) {
                                fileCov.functions.covered++;
                            }
                            break;
                                
                        default:
                            // Unknown type - treat as statement coverage for safety
                            fileCov.lines.total++;
                            if (count > 0) {
                                fileCov.lines.covered++;
                                fileCov.coveredLineNumbers.add(lineNumber);
                            }
                            break;
                        }
                    }
                }

                // Parse metrics if available (some Clover variants include summary metrics)
                if (file.metrics) {
                    const metrics = file.metrics;
                    
                    // Override with metrics if they provide more accurate counts
                    const statements = parseIntSafe(metrics['@_statements']);
                    const coveredStatements = parseIntSafe(metrics['@_coveredstatements']);
                    const methods = parseIntSafe(metrics['@_methods']);
                    const coveredMethods = parseIntSafe(metrics['@_coveredmethods']);
                    const conditionals = parseIntSafe(metrics['@_conditionals']);
                    const coveredConditionals = parseIntSafe(metrics['@_coveredconditionals']);
                    
                    if (statements !== null && coveredStatements !== null) {
                        fileCov.lines.total = statements;
                        fileCov.lines.covered = coveredStatements;
                    }
                    
                    if (methods !== null && coveredMethods !== null) {
                        fileCov.functions.total = methods;
                        fileCov.functions.covered = coveredMethods;
                    }
                    
                    if (conditionals !== null && coveredConditionals !== null) {
                        fileCov.branches.total = conditionals;
                        fileCov.branches.covered = coveredConditionals;
                    }
                }
            }
        }

        const files = Object.values(filesMap);

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
        // Provide clear error messaging for different failure modes
        if (error instanceof Error) {
            if (error.message.includes('XML content contains potentially dangerous constructs')) {
                throw new Error(`Clover XML security validation failed: ${error.message}`);
            }
            if (error.message.includes('excessive nesting')) {
                throw new Error(`Clover XML file too complex: ${error.message}`);
            }
        }
        throw new Error(`Failed to parse Clover XML: ${error}`);
    }
}

/**
 * Read Clover XML file from disk and parse it
 */
export function parseCloverFile(filePath: string): ProjectCov {
    try {
        const xmlContent = readFileSync(filePath, 'utf8');
        return parseClover(xmlContent);
    } catch (error) {
        throw new Error(`Failed to read Clover file ${filePath}: ${error}`);
    }
}

// Helper functions

/**
 * Create empty project coverage structure
 */
function createEmptyProjectCov(): ProjectCov {
    return { 
        files: [], 
        totals: { 
            lines: { covered: 0, total: 0 }, 
            branches: { covered: 0, total: 0 }, 
            functions: { covered: 0, total: 0 } 
        } 
    };
}

/**
 * Safely parse integer from string, return null if invalid
 */
function parseIntSafe(value: any): number | null {
    if (value === undefined || value === null) return null;
    const parsed = parseInt(String(value), 10);
    return isNaN(parsed) ? null : parsed;
}

/**
 * Sanitize file path to prevent directory traversal attacks
 */
function sanitizeFilePath(filePath: string): string {
    if (!filePath || typeof filePath !== 'string') {
        return '';
    }
    
    // Remove null bytes and control characters
    let sanitized = filePath.replace(/[\x00-\x1f\x7f-\x9f]/g, '');
    
    // Resolve path traversal attempts
    sanitized = sanitized.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');
    
    // Normalize path separators
    sanitized = sanitized.replace(/\\/g, '/');
    
    // Remove leading slashes for relative paths
    sanitized = sanitized.replace(/^\/+/, '');
    
    return sanitized;
}