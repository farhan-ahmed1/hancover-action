import { readFileSync } from 'fs';
import { FileCov, ProjectCov } from '../schema.js';

export function parseLCOV(data: string): ProjectCov {
    const files: FileCov[] = [];
    let currentFile: Partial<FileCov> | null = null;
    
    // Track function definitions per file
    const functionDefs = new Map<string, Set<string>>(); // path -> function names
    const functionHits = new Map<string, Map<string, number>>(); // path -> (function name -> max hits)

    const lines = data.split('\n');
    
    for (const line of lines) {
        const trimmed = line.trim();
        
        if (trimmed.startsWith('SF:')) {
            // Start of file - save previous if exists
            if (currentFile && currentFile.path) {
                finalizeCoverageFile(currentFile, functionDefs, functionHits, files);
            }
            
            currentFile = {
                path: trimmed.substring(3).trim(),
                lines: { covered: 0, total: 0 },
                branches: { covered: 0, total: 0 },
                functions: { covered: 0, total: 0 },
                coveredLineNumbers: new Set<number>()
            };
            
        } else if (trimmed.startsWith('DA:') && currentFile) {
            // Line coverage: DA:<line>,<hits>
            const [lineStr, hitsStr] = trimmed.substring(3).split(',');
            const lineNumber = parseInt(lineStr, 10);
            const hits = parseInt(hitsStr, 10);
            
            if (!isNaN(lineNumber) && !isNaN(hits)) {
                currentFile.lines!.total++;
                if (hits > 0) {
                    currentFile.lines!.covered++;
                    currentFile.coveredLineNumbers!.add(lineNumber);
                }
            }
            
        } else if (trimmed.startsWith('FN:') && currentFile) {
            // Function definition: FN:<start_line>,<function_name>
            const colonIndex = trimmed.indexOf(':', 3);
            if (colonIndex > 0) {
                const functionName = trimmed.substring(colonIndex + 1);
                const filePath = currentFile.path!;
                
                if (!functionDefs.has(filePath)) {
                    functionDefs.set(filePath, new Set());
                }
                functionDefs.get(filePath)!.add(functionName);
            }
            
        } else if (trimmed.startsWith('FNDA:') && currentFile) {
            // Function hit data: FNDA:<hits>,<function_name>
            const commaIndex = trimmed.indexOf(',', 5);
            if (commaIndex > 0) {
                const hitsStr = trimmed.substring(5, commaIndex);
                const functionName = trimmed.substring(commaIndex + 1);
                const hits = parseInt(hitsStr, 10);
                
                if (!isNaN(hits)) {
                    const filePath = currentFile.path!;
                    if (!functionHits.has(filePath)) {
                        functionHits.set(filePath, new Map());
                    }
                    const fileHits = functionHits.get(filePath)!;
                    const currentHits = fileHits.get(functionName) || 0;
                    fileHits.set(functionName, Math.max(currentHits, hits));
                }
            }
            
        } else if (trimmed.startsWith('BRDA:') && currentFile) {
            // Branch coverage: BRDA:<line>,<block>,<branch>,<taken>
            const parts = trimmed.substring(5).split(',');
            if (parts.length >= 4) {
                const taken = parts[3];
                if (taken !== '-') {
                    const takenCount = parseInt(taken, 10);
                    if (!isNaN(takenCount)) {
                        currentFile.branches!.total++;
                        if (takenCount > 0) {
                            currentFile.branches!.covered++;
                        }
                    }
                }
            }
            
        } else if (trimmed === 'end_of_record' && currentFile) {
            // End of current file
            if (currentFile.path) {
                finalizeCoverageFile(currentFile, functionDefs, functionHits, files);
            }
            currentFile = null;
        }
    }
    
    // Handle case where file doesn't end with end_of_record
    if (currentFile && currentFile.path) {
        finalizeCoverageFile(currentFile, functionDefs, functionHits, files);
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
}

function finalizeCoverageFile(
    currentFile: Partial<FileCov>, 
    functionDefs: Map<string, Set<string>>, 
    functionHits: Map<string, Map<string, number>>, 
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
    
    files.push(currentFile as FileCov);
}

// Read LCOV file from disk and parse it
export function parseLcovFile(filePath: string): ProjectCov {
    try {
        const data = readFileSync(filePath, 'utf8');
        return parseLCOV(data);
    } catch (error) {
        throw new Error(`Failed to read LCOV file ${filePath}: ${error}`);
    }
}