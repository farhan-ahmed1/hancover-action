import { XMLParser } from 'fast-xml-parser';
import { readFileSync } from 'fs';
import { CoverageBundle, FileCov } from '../schema.js';

export function parseCobertura(xmlContent: string): CoverageBundle {
    try {
        const parser = new XMLParser({
            ignoreAttributes: false,
            attributeNamePrefix: '@_',
            // Disable DTD processing for security and performance
            processEntities: false,
            ignoreDeclaration: true,
            trimValues: true
        });
        
        const result = parser.parse(xmlContent);
        const coverage = result.coverage;
        
        if (!coverage) {
            return { files: [] };
        }

        const files: FileCov[] = [];

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
                if (!cls || !cls['@_filename']) continue;
                
                const filePath = cls['@_filename'];
                const lines = [];
                let linesCovered = 0;
                let linesTotal = 0;
                let branchesCovered = 0;
                let branchesTotal = 0;

                // Parse line coverage
                if (cls.lines && cls.lines.line) {
                    const lineArray = Array.isArray(cls.lines.line) 
                        ? cls.lines.line 
                        : [cls.lines.line];

                    for (const line of lineArray) {
                        if (line && line['@_number'] !== undefined && line['@_hits'] !== undefined) {
                            const lineNumber = parseInt(line['@_number'], 10);
                            const hits = parseInt(line['@_hits'], 10);
                            const isBranch = line['@_branch'] === 'true';
                            
                            const lineCov: any = { line: lineNumber, hits };
                            
                            // Handle branch information
                            if (isBranch && line['@_condition-coverage']) {
                                const conditionCoverage = line['@_condition-coverage'];
                                const match = conditionCoverage.match(/(\d+)%\s*\((\d+)\/(\d+)\)/);
                                if (match) {
                                    const branchesHit = parseInt(match[2], 10);
                                    const totalBranchesForLine = parseInt(match[3], 10);
                                    lineCov.isBranch = true;
                                    lineCov.branchesHit = branchesHit;
                                    lineCov.branchesTotal = totalBranchesForLine;
                                    
                                    branchesCovered += branchesHit;
                                    branchesTotal += totalBranchesForLine;
                                }
                            }
                            
                            lines.push(lineCov);
                            linesTotal++;
                            if (hits > 0) linesCovered++;
                        }
                    }
                }

                files.push({
                    path: filePath,
                    lines,
                    summary: { 
                        linesCovered, 
                        linesTotal,
                        branchesCovered: branchesTotal > 0 ? branchesCovered : undefined,
                        branchesTotal: branchesTotal > 0 ? branchesTotal : undefined
                    }
                });
            }
        }

        return { files };
    } catch (error) {
        throw new Error(`Failed to parse Cobertura XML: ${error}`);
    }
}

// Read Cobertura file from disk and parse it
export function parseCoberturaFile(filePath: string): CoverageBundle {
    try {
        const xmlContent = readFileSync(filePath, 'utf8');
        return parseCobertura(xmlContent);
    } catch (error) {
        throw new Error(`Failed to read Cobertura file ${filePath}: ${error}`);
    }
}