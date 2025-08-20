import { FileCov, PkgCov } from './schema.js';
import { Config, loadConfig, matchesPatterns } from './config.js';
import * as path from 'path';
import * as core from '@actions/core';

export type GroupSummary = {
    name: string;
    files: FileCov[];
    coveragePct: number;
    linesCovered: number;
    linesTotal: number;
};

/**
 * Enhanced package grouping with config support:
 * 1. Apply base grouping (smart defaults)
 * 2. Apply overlay rules from config
 * 3. Return both detailed packages and top-level summary
 */
export function groupPackages(files: FileCov[], config?: Required<Config>): {
    pkgRows: PkgCov[];
    topLevelRows: PkgCov[];
} {
    if (files.length === 0) {
        return { pkgRows: [], topLevelRows: [] };
    }

    const resolvedConfig = config || loadConfig();
    core.debug(`Grouping ${files.length} files with config: ${JSON.stringify(resolvedConfig, null, 2)}`);

    // Step 1: Base grouping (smart defaults)
    const basePackages = applyBaseGrouping(files, resolvedConfig);
    
    // Step 2: Apply overlay rules from config
    const overlayPackages = applyOverlayRules(basePackages, files, resolvedConfig);
    
    // Step 3: Compute top-level summary (always based on first path segment)
    const topLevelPackages = computeTopLevelSummary(files);
    
    // Sort both results
    overlayPackages.sort((a, b) => a.name.localeCompare(b.name));
    topLevelPackages.sort((a, b) => a.name.localeCompare(b.name));
    
    core.info(`Grouped into ${overlayPackages.length} detailed packages and ${topLevelPackages.length} top-level packages`);
    
    return {
        pkgRows: overlayPackages,
        topLevelRows: topLevelPackages
    };
}

/**
 * Apply base grouping logic (the original smart grouping)
 */
function applyBaseGrouping(files: FileCov[], config: Required<Config>): PkgCov[] {
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

    // Step 2: Check if one group dominates (≥promoteThreshold% of files)
    const totalFiles = files.length;
    let dominantGroup: string | null = null;

    if (config.fallback.smartDepth === 'auto') {
        for (const [groupName, groupFiles] of topLevelGroups) {
            if (groupFiles.length / totalFiles >= (config.fallback.promoteThreshold ?? 0.8)) {
                dominantGroup = groupName;
                break;
            }
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

    return packages;
}

/**
 * Apply overlay rules from config to reassign files
 */
function applyOverlayRules(basePackages: PkgCov[], allFiles: FileCov[], config: Required<Config>): PkgCov[] {
    if (config.groups.length === 0) {
        return basePackages;
    }

    // Track which files have been claimed by overlay rules
    const claimedFiles = new Set<string>();
    const overlayPackages: PkgCov[] = [];

    // Process overlay rules in order
    for (const rule of config.groups) {
        const matchingFiles: FileCov[] = [];

        for (const file of allFiles) {
            if (claimedFiles.has(file.path)) continue;

            // Check if file matches include patterns
            const matches = matchesPatterns(file.path, rule.patterns);
            
            // Check if file should be excluded
            const excluded = rule.exclude ? matchesPatterns(file.path, rule.exclude) : false;

            if (matches && !excluded) {
                matchingFiles.push(file);
                claimedFiles.add(file.path);
            }
        }

        if (matchingFiles.length > 0) {
            overlayPackages.push(createPackage(rule.name, matchingFiles));
            core.debug(`Overlay rule '${rule.name}' matched ${matchingFiles.length} files`);
        }
    }

    // Add remaining unclaimed files using base grouping
    const unclaimedFiles = allFiles.filter(f => !claimedFiles.has(f.path));
    if (unclaimedFiles.length > 0) {
        const remainingBase = applyBaseGrouping(unclaimedFiles, config);
        overlayPackages.push(...remainingBase);
    }

    return overlayPackages;
}

/**
 * Compute top-level summary based on first path segment only
 */
function computeTopLevelSummary(files: FileCov[]): PkgCov[] {
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

    // Convert to packages
    const packages: PkgCov[] = [];
    for (const [groupName, groupFiles] of topLevelGroups) {
        packages.push(createPackage(groupName, groupFiles));
    }

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
    const { pkgRows } = groupPackages(bundle.files);
    const result = new Map<string, FileCov[]>();
    
    for (const pkg of pkgRows) {
        result.set(pkg.name, pkg.files);
    }
    
    return result;
}

/**
 * Simple wrapper that returns just the detailed packages (for backwards compatibility)
 */
export function groupPackagesLegacy(files: FileCov[]): PkgCov[] {
    return groupPackages(files).pkgRows;
}
