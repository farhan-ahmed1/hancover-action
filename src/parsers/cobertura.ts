import { XMLParser } from 'fast-xml-parser';
import { readFileSync } from 'fs';
import { FileCov, ProjectCov } from '../schema.js';
import { validateXmlSecurity } from '../fs-limits.js';

/**
 * Parse Cobertura XML coverage format
 * 
 * Cobertura XML structure:
 * <coverage line-rate="0.8" branch-rate="0.7" version="1.0">
 *   <packages>
 *     <package name="com.example" line-rate="0.8" branch-rate="0.7">
 *       <classes>
 *         <class name="Example" filename="src/Example.java" line-rate="0.8" branch-rate="0.7">
 *           <methods>
 *             <method name="method1" signature="()" line-rate="1.0" branch-rate="1.0">
 *               <lines>
 *                 <line number="1" hits="5"/>
 *               </lines>
 *             </method>
 *           </methods>
 *           <lines>
 *             <line number="1" hits="5" branch="true" condition-coverage="50% (1/2)"/>
 *             <line number="2" hits="0"/>
 *           </lines>
 *         </class>
 *       </classes>
 *     </package>
 *   </packages>
 * </coverage>
 * 
 * Security measures:
 * - XML security validation (DTD/Entity protection)
 * - Safe XML parser configuration  
 * - Input validation and sanitization
 * - Path sanitization to prevent directory traversal
 * - Bounded parsing (nested structure limits handled by security validator)
 */
export function parseCobertura(xmlContent: string): ProjectCov {
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

        const filesMap: Record<string, FileCov> = {};

        // Handle different Cobertura XML structures
        let packages = [];
        if (coverage.packages) {
            if (coverage.packages.package) {
                packages = Array.isArray(coverage.packages.package) 
                    ? coverage.packages.package 
                    : [coverage.packages.package];
            }
        }

        for (const pkg of packages) {
            if (!pkg || !pkg.classes) continue;
            
            const classes = Array.isArray(pkg.classes.class) 
                ? pkg.classes.class 
                : pkg.classes.class ? [pkg.classes.class] : [];

            for (const cls of classes) {
                if (!cls) continue;
                
                // Prefer filename attribute, fallback to package + class name
                let filePath = cls['@_filename'];
                if (!filePath) {
                    const packageName = pkg['@_name'] || '';
                    const className = cls['@_name'] || '';
                    filePath = `${packageName.replace(/\./g, '/')}/${className.replace(/\./g, '/')}.js`;
                }

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
                        package: pkg['@_name']
                    };
                }
                
                const file = filesMap[normalizedPath];

                // Parse methods → functions
                if (cls.methods && cls.methods.method) {
                    const methods = Array.isArray(cls.methods.method) 
                        ? cls.methods.method 
                        : [cls.methods.method];

                    for (const method of methods) {
                        if (!method || !method['@_name']) continue;
                        
                        file.functions.total++;
                        
                        // Check if method has any covered lines
                        let methodHasCoveredLines = false;
                        if (method.lines && method.lines.line) {
                            const methodLines = Array.isArray(method.lines.line) 
                                ? method.lines.line 
                                : [method.lines.line];
                            
                            for (const line of methodLines) {
                                if (line && line['@_hits']) {
                                    const hits = parseIntSafe(line['@_hits']);
                                    if (hits !== null && hits > 0) {
                                        methodHasCoveredLines = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if (methodHasCoveredLines) {
                            file.functions.covered++;
                        }
                    }
                }

                // Parse lines → statements & branches
                if (cls.lines && cls.lines.line) {
                    const lines = Array.isArray(cls.lines.line) 
                        ? cls.lines.line 
                        : [cls.lines.line];

                    for (const line of lines) {
                        if (!line || line['@_number'] === undefined || line['@_hits'] === undefined) continue;
                        
                        const lineNumber = parseIntSafe(line['@_number']);
                        const hits = parseIntSafe(line['@_hits']);
                        
                        if (lineNumber === null || hits === null) continue;
                        
                        // Count line/statement coverage
                        file.lines.total++;
                        if (hits > 0) {
                            file.lines.covered++;
                            file.coveredLineNumbers.add(lineNumber);
                        }

                        // Parse branch coverage from condition-coverage attribute
                        if (line['@_condition-coverage']) {
                            const conditionCoverage = line['@_condition-coverage'];
                            // Format: "x% (a/b)" where a=covered, b=total
                            // Only match if it starts with a percentage
                            const match = conditionCoverage.match(/^\d+%\s*\((\d+)\/(\d+)\)/);
                            if (match) {
                                const branchesCovered = parseIntSafe(match[1]);
                                const branchesTotal = parseIntSafe(match[2]);
                                
                                if (branchesCovered !== null && branchesTotal !== null) {
                                    file.branches.covered += branchesCovered;
                                    file.branches.total += branchesTotal;
                                }
                            }
                        }
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
                throw new Error(`Cobertura XML security validation failed: ${error.message}`);
            }
            if (error.message.includes('excessive nesting')) {
                throw new Error(`Cobertura XML file too complex: ${error.message}`);
            }
        }
        throw new Error(`Failed to parse Cobertura XML: ${error}`);
    }
}

/**
 * Read Cobertura XML file from disk and parse it
 */
export function parseCoberturaFile(filePath: string): ProjectCov {
    try {
        const xmlContent = readFileSync(filePath, 'utf8');
        return parseCobertura(xmlContent);
    } catch (error) {
        throw new Error(`Failed to read Cobertura file ${filePath}: ${error}`);
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
    if (!filePath) return '';
    
    // Remove any directory traversal attempts
    let sanitized = filePath.replace(/\.\./g, '');
    
    // Normalize path separators and remove leading slashes
    sanitized = sanitized.replace(/\\/g, '/');
    sanitized = sanitized.replace(/^\/+/, '');
    
    // Remove any remaining dangerous patterns
    sanitized = sanitized.replace(/\/\.+\//g, '/');
    
    return sanitized || 'unknown';
}