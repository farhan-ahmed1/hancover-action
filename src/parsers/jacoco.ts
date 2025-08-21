import { XMLParser } from 'fast-xml-parser';
import { readFileSync } from 'fs';
import { FileCov, ProjectCov } from '../schema.js';
import { validateXmlSecurity } from '../fs-limits.js';
import sanitize from 'sanitize-filename';

/**
 * Parse JaCoCo XML coverage format
 * 
 * JaCoCo XML structure:
 * <report name="project">
 *   <sessioninfo id="host1" start="1234567890" dump="1234567900"/>
 *   <package name="com/example/package">
 *     <class name="com/example/package/ClassName" sourcefilename="ClassName.java">
 *       <method name="methodName" desc="(I)V" line="10">
 *         <counter type="INSTRUCTION" missed="0" covered="5"/>
 *         <counter type="BRANCH" missed="1" covered="2"/>
 *         <counter type="LINE" missed="0" covered="2"/>
 *         <counter type="COMPLEXITY" missed="0" covered="1"/>
 *         <counter type="METHOD" missed="0" covered="1"/>
 *       </method>
 *       <counter type="INSTRUCTION" missed="0" covered="5"/>
 *       <counter type="BRANCH" missed="1" covered="2"/>
 *       <counter type="LINE" missed="0" covered="2"/>
 *       <counter type="COMPLEXITY" missed="0" covered="1"/>
 *       <counter type="METHOD" missed="0" covered="1"/>
 *       <counter type="CLASS" missed="0" covered="1"/>
 *     </class>
 *     <sourcefile name="ClassName.java">
 *       <line nr="10" mi="0" ci="3" mb="0" cb="2"/>
 *       <line nr="11" mi="1" ci="0" mb="1" cb="0"/>
 *       <counter type="INSTRUCTION" missed="1" covered="3"/>
 *       <counter type="BRANCH" missed="1" covered="2"/>
 *       <counter type="LINE" missed="1" covered="1"/>
 *       <counter type="COMPLEXITY" missed="0" covered="1"/>
 *       <counter type="METHOD" missed="0" covered="1"/>
 *       <counter type="CLASS" missed="0" covered="1"/>
 *     </sourcefile>
 *     <counter type="INSTRUCTION" missed="1" covered="3"/>
 *     <counter type="BRANCH" missed="1" covered="2"/>
 *     <counter type="LINE" missed="1" covered="1"/>
 *     <counter type="COMPLEXITY" missed="0" covered="1"/>
 *     <counter type="METHOD" missed="0" covered="1"/>
 *     <counter type="CLASS" missed="0" covered="1"/>
 *   </package>
 *   <counter type="INSTRUCTION" missed="1" covered="3"/>
 *   <counter type="BRANCH" missed="1" covered="2"/>
 *   <counter type="LINE" missed="1" covered="1"/>
 *   <counter type="COMPLEXITY" missed="0" covered="1"/>
 *   <counter type="METHOD" missed="0" covered="1"/>
 *   <counter type="CLASS" missed="0" covered="1"/>
 * </report>
 * 
 * Counter types:
 * - INSTRUCTION: JVM bytecode instructions
 * - BRANCH: Conditional branches (if/else, switch, etc.)
 * - LINE: Source code lines 
 * - COMPLEXITY: Cyclomatic complexity
 * - METHOD: Methods/functions
 * - CLASS: Classes
 * 
 * Line attributes:
 * - nr: line number
 * - mi: missed instructions
 * - ci: covered instructions  
 * - mb: missed branches
 * - cb: covered branches
 * 
 * Security measures:
 * - XML security validation (DTD/Entity protection)
 * - Safe XML parser configuration  
 * - Input validation and sanitization
 * - Path sanitization to prevent directory traversal
 * - Integer overflow protection
 * - Bounded parsing (nested structure limits handled by security validator)
 */
export function parseJaCoCo(xmlContent: string): ProjectCov {
    try {
        // Handle empty content gracefully
        if (!xmlContent || xmlContent.trim() === '') {
            return createEmptyProjectCov();
        }
        
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
        const report = result.report;
        
        if (!report) {
            return createEmptyProjectCov();
        }

        const filesMap: Record<string, FileCov> = {};

        // Handle packages - can be single object or array
        let packages = [];
        if (report.package) {
            packages = Array.isArray(report.package) 
                ? report.package 
                : [report.package];
        }

        for (const pkg of packages) {
            if (!pkg) continue;
            
            const packageName = pkg['@_name'] || '';
            const processedFiles = new Set<string>();

            // First pass: Process sourcefiles for line and branch coverage
            let sourcefiles = [];
            if (pkg.sourcefile) {
                sourcefiles = Array.isArray(pkg.sourcefile) 
                    ? pkg.sourcefile 
                    : [pkg.sourcefile];
            }

            for (const sourcefile of sourcefiles) {
                if (!sourcefile || !sourcefile['@_name']) continue;
                
                const sourcefileName = sourcefile['@_name'];
                
                // Construct file path from package and sourcefile name
                let filePath: string;
                if (packageName) {
                    filePath = `${packageName}/${sourcefileName}`;
                } else {
                    filePath = sourcefileName;
                }

                // Validate file path to prevent directory traversal
                const normalizedPath = sanitizeFilePath(filePath);
                processedFiles.add(normalizedPath);

                // Get or create file entry
                if (!filesMap[normalizedPath]) {
                    filesMap[normalizedPath] = {
                        path: normalizedPath,
                        lines: { covered: 0, total: 0 },
                        branches: { covered: 0, total: 0 },
                        functions: { covered: 0, total: 0 },
                        coveredLineNumbers: new Set<number>(),
                        package: packageName || undefined
                    };
                }
                
                const file = filesMap[normalizedPath];

                // Parse individual line coverage from sourcefile
                if (sourcefile.line) {
                    const lines = Array.isArray(sourcefile.line) 
                        ? sourcefile.line 
                        : [sourcefile.line];
                    
                    for (const line of lines) {
                        if (!line || line['@_nr'] === undefined) continue;
                        
                        const lineNumber = parseIntSafe(line['@_nr']);
                        const missedInstructions = Math.max(0, parseIntSafe(line['@_mi']) || 0);
                        const coveredInstructions = Math.max(0, parseIntSafe(line['@_ci']) || 0);
                        const missedBranches = Math.max(0, parseIntSafe(line['@_mb']) || 0);
                        const coveredBranches = Math.max(0, parseIntSafe(line['@_cb']) || 0);
                        
                        if (lineNumber === null || lineNumber <= 0) continue;
                        
                        // Line coverage - a line is covered if it has any covered instructions
                        if (coveredInstructions > 0 || missedInstructions > 0) {
                            file.lines.total++;
                            if (coveredInstructions > 0) {
                                file.lines.covered++;
                                file.coveredLineNumbers.add(lineNumber);
                            }
                        }
                        
                        // Branch coverage - add all branches for this line
                        const totalBranches = missedBranches + coveredBranches;
                        if (totalBranches > 0) {
                            file.branches.total += totalBranches;
                            file.branches.covered += coveredBranches;
                        }
                    }
                }

                // Extract aggregated counters from sourcefile for validation/fallback
                const sourcefileCounters = extractCounters(sourcefile.counter);
                
                // Use sourcefile counters as authoritative source if line-level data is missing
                if (file.lines.total === 0 && sourcefileCounters.line.total > 0) {
                    file.lines.total = sourcefileCounters.line.total;
                    file.lines.covered = sourcefileCounters.line.covered;
                }
                
                if (file.branches.total === 0 && sourcefileCounters.branch.total > 0) {
                    file.branches.total = sourcefileCounters.branch.total;
                    file.branches.covered = sourcefileCounters.branch.covered;
                }
                
                // Set method coverage from sourcefile counters as initial values
                if (sourcefileCounters.method.total > 0) {
                    file.functions.total = sourcefileCounters.method.total;
                    file.functions.covered = sourcefileCounters.method.covered;
                }
            }

            // Second pass: Process classes for method details (this may override sourcefile method counts)
            let classes = [];
            if (pkg.class) {
                classes = Array.isArray(pkg.class) 
                    ? pkg.class 
                    : [pkg.class];
            }

            for (const cls of classes) {
                if (!cls) continue;
                
                const sourcefileName = cls['@_sourcefilename'];
                if (!sourcefileName) continue;
                
                // Construct file path from package and sourcefile name
                let filePath: string;
                if (packageName) {
                    filePath = `${packageName}/${sourcefileName}`;
                } else {
                    filePath = sourcefileName;
                }

                // Validate file path to prevent directory traversal
                const normalizedPath = sanitizeFilePath(filePath);

                // Get or create file entry (in case not processed by sourcefile)
                if (!filesMap[normalizedPath]) {
                    filesMap[normalizedPath] = {
                        path: normalizedPath,
                        lines: { covered: 0, total: 0 },
                        branches: { covered: 0, total: 0 },
                        functions: { covered: 0, total: 0 },
                        coveredLineNumbers: new Set<number>(),
                        package: packageName || undefined
                    };
                }
                
                const file = filesMap[normalizedPath];

                // Parse methods for detailed function coverage - prefer class method details over counters
                if (cls.method) {
                    const methods = Array.isArray(cls.method) 
                        ? cls.method 
                        : [cls.method];

                    // Count methods from classes (this is more accurate than counter data)
                    let classFunctionTotal = 0;
                    let classFunctionCovered = 0;

                    for (const method of methods) {
                        if (!method || !method['@_name']) continue;
                        
                        classFunctionTotal++;
                        
                        // Check if method is covered by looking at its counters
                        const methodCounters = extractCounters(method.counter);
                        if (methodCounters.method.covered > 0) {
                            classFunctionCovered++;
                        }
                    }
                    
                    // Use class method data if we found methods
                    if (classFunctionTotal > 0) {
                        file.functions.total = classFunctionTotal;
                        file.functions.covered = classFunctionCovered;
                    }
                }

                // Use class counters as fallback if no method data exists
                if (file.functions.total === 0) {
                    const classCounters = extractCounters(cls.counter);
                    if (classCounters.method.total > 0) {
                        file.functions.total = classCounters.method.total;
                        file.functions.covered = classCounters.method.covered;
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
                throw new Error(`JaCoCo XML security validation failed: ${error.message}`);
            }
            if (error.message.includes('excessive nesting')) {
                throw new Error(`JaCoCo XML file too complex: ${error.message}`);
            }
        }
        throw new Error(`Failed to parse JaCoCo XML: ${error}`);
    }
}

/**
 * Read JaCoCo XML file from disk and parse it
 */
export function parseJaCoCoFile(filePath: string): ProjectCov {
    try {
        const xmlContent = readFileSync(filePath, 'utf8');
        return parseJaCoCo(xmlContent);
    } catch (error) {
        throw new Error(`Failed to read JaCoCo file ${filePath}: ${error}`);
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
 * Extract coverage counters from JaCoCo counter elements
 */
function extractCounters(counters: any): {
    instruction: { covered: number; total: number };
    branch: { covered: number; total: number };
    line: { covered: number; total: number };
    complexity: { covered: number; total: number };
    method: { covered: number; total: number };
    class: { covered: number; total: number };
} {
    const result = {
        instruction: { covered: 0, total: 0 },
        branch: { covered: 0, total: 0 },
        line: { covered: 0, total: 0 },
        complexity: { covered: 0, total: 0 },
        method: { covered: 0, total: 0 },
        class: { covered: 0, total: 0 }
    };

    if (!counters) return result;

    const counterArray = Array.isArray(counters) ? counters : [counters];
    
    for (const counter of counterArray) {
        if (!counter || !counter['@_type']) continue;
        
        const type = counter['@_type'].toLowerCase();
        const missed = parseIntSafe(counter['@_missed']) || 0;
        const covered = parseIntSafe(counter['@_covered']) || 0;
        const total = missed + covered;
        
        switch (type) {
        case 'instruction':
            result.instruction.covered = covered;
            result.instruction.total = total;
            break;
        case 'branch':
            result.branch.covered = covered;
            result.branch.total = total;
            break;
        case 'line':
            result.line.covered = covered;
            result.line.total = total;
            break;
        case 'complexity':
            result.complexity.covered = covered;
            result.complexity.total = total;
            break;
        case 'method':
            result.method.covered = covered;
            result.method.total = total;
            break;
        case 'class':
            result.class.covered = covered;
            result.class.total = total;
            break;
        }
    }

    return result;
}

/**
 * Sanitize file path to prevent directory traversal attacks
 */
function sanitizeFilePath(filePath: string): string {
    if (!filePath || typeof filePath !== 'string') {
        return '';
    }
    
    // Split path into segments and sanitize each segment individually
    const segments = filePath.split(/[/\\]+/);
    const sanitizedSegments = segments
        .map(segment => sanitize(segment))
        .filter(segment => segment && segment !== '.' && segment !== '..');
    
    return sanitizedSegments.join('/');
}