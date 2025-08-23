import { FileCov, ProjectCov, PkgCov } from './schema.js';
import { pct } from './group.js';

export interface ChangedLinesByFile {
    [filePath: string]: Set<number>;
}

export interface ChangesCoverage {
    files: FileCov[];
    packages: PkgCov[];
    totals: {
        lines: { covered: number; total: number };
        branches: { covered: number; total: number };
        functions: { covered: number; total: number };
    };
}

/**
 * Compute code-changes coverage: "Of the lines I touched in this PR, what % is covered?"
 */
export function computeChangesCoverage(
    project: ProjectCov, 
    changedLinesByFile: ChangedLinesByFile
): ChangesCoverage {
    const changesFiles: FileCov[] = [];
    
    for (const file of project.files) {
        const changedLines = changedLinesByFile[file.path];
        if (!changedLines || changedLines.size === 0) {
            continue;
        }
        
        // Count how many of the changed lines are covered
        let coveredChangedLines = 0;
        for (const lineNumber of changedLines) {
            if (file.coveredLineNumbers.has(lineNumber)) {
                coveredChangedLines++;
            }
        }
        
        // Create a file coverage object for just the changed lines
        const changesFile: FileCov = {
            path: file.path,
            lines: { covered: coveredChangedLines, total: changedLines.size },
            branches: { covered: 0, total: 0 }, // Not tracking branches for changes
            functions: { covered: 0, total: 0 }, // Not tracking functions for changes
            coveredLineNumbers: new Set(
                Array.from(changedLines).filter(line => file.coveredLineNumbers.has(line))
            ),
            package: file.package
        };
        
        changesFiles.push(changesFile);
    }
    
    // Group the changes files into packages (reuse existing package assignments)
    const packageMap = new Map<string, FileCov[]>();
    
    for (const file of changesFiles) {
        const packageName = file.package || 'root';
        if (!packageMap.has(packageName)) {
            packageMap.set(packageName, []);
        }
        packageMap.get(packageName)!.push(file);
    }
    
    // Create package coverage objects
    const packages: PkgCov[] = [];
    for (const [packageName, files] of packageMap) {
        const totals = {
            lines: { covered: 0, total: 0 },
            branches: { covered: 0, total: 0 },
            functions: { covered: 0, total: 0 }
        };
        
        for (const file of files) {
            totals.lines.covered += file.lines.covered;
            totals.lines.total += file.lines.total;
        }
        
        packages.push({ name: packageName, files, totals });
    }
    
    // Sort packages by name
    packages.sort((a, b) => a.name.localeCompare(b.name));
    
    // Compute overall totals
    const totals = {
        lines: { covered: 0, total: 0 },
        branches: { covered: 0, total: 0 },
        functions: { covered: 0, total: 0 }
    };
    
    for (const file of changesFiles) {
        totals.lines.covered += file.lines.covered;
        totals.lines.total += file.lines.total;
    }
    
    return { files: changesFiles, packages, totals };
}

/**
 * Parse git diff output to extract changed line numbers per file
 */
export function parseGitDiff(gitDiffOutput: string): ChangedLinesByFile {
    const result: ChangedLinesByFile = {};
    const lines = gitDiffOutput.split('\n');
    
    let currentFile: string | null = null;
    
    for (const line of lines) {
        // Track file renames: --- a/old +++ b/new
        if (line.startsWith('+++')) {
            const match = line.match(/^\+\+\+ b\/(.+)$/);
            if (match) {
                currentFile = match[1];
                result[currentFile] = new Set();
            }
        }
        // Parse hunk headers: @@ -a,b +c,d @@
        else if (line.startsWith('@@') && currentFile) {
            const match = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
            if (match) {
                const startLine = parseInt(match[1], 10);
                const lineCount = match[2] ? parseInt(match[2], 10) : 1;
                
                // Add all lines in this hunk as changed
                for (let i = 0; i < lineCount; i++) {
                    result[currentFile].add(startLine + i);
                }
            }
        }
    }
    
    return result;
}

/**
 * Compute delta coverage between PR and main
 */
export function computeDeltaCoverage(
    prPackages: PkgCov[],
    mainPackages: PkgCov[]
): DeltaCoverage {
    // Build index of main packages by name
    const mainIndex = new Map<string, PkgCov>();
    for (const pkg of mainPackages) {
        mainIndex.set(pkg.name, pkg);
    }
    
    // Build index of PR packages by name
    const prIndex = new Map<string, PkgCov>();
    for (const pkg of prPackages) {
        prIndex.set(pkg.name, pkg);
    }
    
    // Get union of all package names
    const allPackageNames = new Set([
        ...prPackages.map(p => p.name),
        ...mainPackages.map(p => p.name)
    ]);
    
    const deltaPackages: DeltaPackage[] = [];
    
    for (const packageName of allPackageNames) {
        const prPkg = prIndex.get(packageName);
        const mainPkg = mainIndex.get(packageName);
        
        const prLinesPct = prPkg ? pct(prPkg.totals.lines.covered, prPkg.totals.lines.total) : 0;
        const mainLinesPct = mainPkg ? pct(mainPkg.totals.lines.covered, mainPkg.totals.lines.total) : 0;
        
        const prBranchesPct = prPkg ? pct(prPkg.totals.branches.covered, prPkg.totals.branches.total) : 0;
        const mainBranchesPct = mainPkg ? pct(mainPkg.totals.branches.covered, mainPkg.totals.branches.total) : 0;
        
        const prFunctionsPct = prPkg ? pct(prPkg.totals.functions.covered, prPkg.totals.functions.total) : 0;
        const mainFunctionsPct = mainPkg ? pct(mainPkg.totals.functions.covered, mainPkg.totals.functions.total) : 0;
        
        deltaPackages.push({
            name: packageName,
            linesDeltas: {
                pr: prLinesPct,
                main: mainLinesPct,
                delta: prLinesPct - mainLinesPct
            },
            branchesDeltas: {
                pr: prBranchesPct,
                main: mainBranchesPct,
                delta: prBranchesPct - mainBranchesPct
            },
            functionsDeltas: {
                pr: prFunctionsPct,
                main: mainFunctionsPct,
                delta: prFunctionsPct - mainFunctionsPct
            }
        });
    }
    
    // Sort by absolute delta (lines) descending
    deltaPackages.sort((a, b) => Math.abs(b.linesDeltas.delta) - Math.abs(a.linesDeltas.delta));
    
    return { packages: deltaPackages };
}

export interface DeltaPackage {
    name: string;
    linesDeltas: { pr: number; main: number; delta: number };
    branchesDeltas: { pr: number; main: number; delta: number };
    functionsDeltas: { pr: number; main: number; delta: number };
}

export interface DeltaCoverage {
    packages: DeltaPackage[];
}
