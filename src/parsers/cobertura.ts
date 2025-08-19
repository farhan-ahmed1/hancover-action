import { XMLParser } from 'fast-xml-parser';
import { readFileSync } from 'fs';
import { FileCov, ProjectCov } from '../schema.js';
import { validateXmlSecurity } from '../fs-limits.js';

export function parseCobertura(xmlContent: string): ProjectCov {
    try {
        // Security validation before parsing
        validateXmlSecurity(xmlContent);
        
        const parser = new XMLParser({
            ignoreAttributes: false,
            attributeNamePrefix: '@_',
            // Security: Disable DTD processing and external entity loading to prevent XXE attacks
            processEntities: false,
            ignoreDeclaration: true,
            trimValues: true,
            // Additional security measures
            allowBooleanAttributes: false
        });
        
        const result = parser.parse(xmlContent);
        const coverage = result.coverage;
        
        if (!coverage) {
            return { 
                files: [], 
                totals: { 
                    lines: { covered: 0, total: 0 }, 
                    branches: { covered: 0, total: 0 }, 
                    functions: { covered: 0, total: 0 } 
                } 
            };
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

                // Get or create file entry
                if (!filesMap[filePath]) {
                    filesMap[filePath] = {
                        path: filePath,
                        lines: { covered: 0, total: 0 },
                        branches: { covered: 0, total: 0 },
                        functions: { covered: 0, total: 0 },
                        coveredLineNumbers: new Set<number>()
                    };
                }
                
                const file = filesMap[filePath];

                // Parse methods → functions
                if (cls.methods && cls.methods.method) {
                    const methods = Array.isArray(cls.methods.method) 
                        ? cls.methods.method 
                        : [cls.methods.method];

                    for (const method of methods) {
                        if (!method) continue;
                        
                        file.functions.total++;
                        
                        // Check if method has any covered lines
                        let methodHasCoveredLines = false;
                        if (method.lines && method.lines.line) {
                            const methodLines = Array.isArray(method.lines.line) 
                                ? method.lines.line 
                                : [method.lines.line];
                            
                            for (const line of methodLines) {
                                if (line && line['@_hits'] && parseInt(line['@_hits'], 10) > 0) {
                                    methodHasCoveredLines = true;
                                    break;
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
                        
                        const lineNumber = parseInt(line['@_number'], 10);
                        const hits = parseInt(line['@_hits'], 10);
                        
                        if (isNaN(lineNumber) || isNaN(hits)) continue;
                        
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
                            const match = conditionCoverage.match(/\((\d+)\/(\d+)\)/);
                            if (match) {
                                const branchesCovered = parseInt(match[1], 10);
                                const branchesTotal = parseInt(match[2], 10);
                                
                                if (!isNaN(branchesCovered) && !isNaN(branchesTotal)) {
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
        throw new Error(`Failed to parse Cobertura XML: ${error}`);
    }
}

// Read Cobertura file from disk and parse it
export function parseCoberturaFile(filePath: string): ProjectCov {
    try {
        const xmlContent = readFileSync(filePath, 'utf8');
        return parseCobertura(xmlContent);
    } catch (error) {
        throw new Error(`Failed to read Cobertura file ${filePath}: ${error}`);
    }
}