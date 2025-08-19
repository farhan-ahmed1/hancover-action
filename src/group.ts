import { FileCov, PkgCov } from './schema.js';
import * as path from 'path';

export type GroupSummary = {
    name: string;
    files: FileCov[];
    coveragePct: number;
    linesCovered: number;
    linesTotal: number;
};

/**
 * Smart package grouping with heuristics:
 * 1. Compute top-level groups = first path segment under repo root
 * 2. If one top-level group holds ≥80% of files, promote one level deeper for that group
 * 3. For monorepo layouts (packages/*, apps/*), treat each workspace directory as its own package
 */
export function groupPackages(files: FileCov[]): PkgCov[] {
    if (files.length === 0) return [];
    
    // Step 1: Compute top-level groups
    const topLevelGroups = new Map<string, FileCov[]>();
    const rootFiles: FileCov[] = [];
    
    for (const file of files) {
        const normalizedPath = path.posix.normalize(file.path);
        const segments = normalizedPath.split('/').filter(s => s.length > 0);
        
        if (segments.length === 0) {
            rootFiles.push(file);
            continue;
        }
        
        const topLevel = segments[0];
        if (!topLevelGroups.has(topLevel)) {
            topLevelGroups.set(topLevel, []);
        }
        topLevelGroups.get(topLevel)!.push(file);
    }
    
    // Add root files if any
    if (rootFiles.length > 0) {
        topLevelGroups.set('root', rootFiles);
    }
    
    // Step 2: Check if one group dominates (≥80% of files)
    const totalFiles = files.length;
    let dominantGroup: string | null = null;
    
    for (const [groupName, groupFiles] of topLevelGroups) {
        if (groupFiles.length / totalFiles >= 0.8) {
            dominantGroup = groupName;
            break;
        }
    }
    
    // Step 3: Build final package structure
    const packages: PkgCov[] = [];
    
    for (const [groupName, groupFiles] of topLevelGroups) {
        if (groupName === dominantGroup && shouldPromoteDeeper(groupFiles)) {
            // Promote one level deeper for the dominant group
            const subGroups = new Map<string, FileCov[]>();
            
            for (const file of groupFiles) {
                const normalizedPath = path.posix.normalize(file.path);
                const segments = normalizedPath.split('/').filter(s => s.length > 0);
                
                let subGroupName = groupName; // fallback
                if (segments.length >= 2) {
                    subGroupName = `${segments[0]}/${segments[1]}`;
                }
                
                if (!subGroups.has(subGroupName)) {
                    subGroups.set(subGroupName, []);
                }
                subGroups.get(subGroupName)!.push(file);
            }
            
            // Add sub-packages
            for (const [subGroupName, subGroupFiles] of subGroups) {
                packages.push(createPackage(subGroupName, subGroupFiles));
            }
        } else {
            // Keep as top-level package
            packages.push(createPackage(groupName, groupFiles));
        }
    }
    
    // Sort packages by name
    packages.sort((a, b) => a.name.localeCompare(b.name));
    
    return packages;
}

function shouldPromoteDeeper(files: FileCov[]): boolean {
    // Check if there are meaningful subdirectories to promote
    const subDirs = new Set<string>();
    
    for (const file of files) {
        const normalizedPath = path.posix.normalize(file.path);
        const segments = normalizedPath.split('/').filter(s => s.length > 0);
        
        if (segments.length >= 2) {
            subDirs.add(segments[1]);
        }
    }
    
    // Only promote if there are at least 2 subdirectories
    return subDirs.size >= 2;
}

function createPackage(name: string, files: FileCov[]): PkgCov {
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
        
        // Set package info on the file for reference
        file.package = name;
    }
    
    return { name, files, totals };
}

/**
 * Utility functions for percentage calculations
 */
export function pct(covered: number, total: number): number {
    return total === 0 ? 100 : (covered / total) * 100;
}

export function rollup(files: FileCov[]): { lines: { covered: number; total: number }; branches: { covered: number; total: number }; functions: { covered: number; total: number } } {
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
    
    return totals;
}

// Legacy function for backwards compatibility
export function groupCoverage(bundle: { files: FileCov[] }): Map<string, FileCov[]> {
    const packages = groupPackages(bundle.files);
    const result = new Map<string, FileCov[]>();
    
    for (const pkg of packages) {
        result.set(pkg.name, pkg.files);
    }
    
    return result;
}
