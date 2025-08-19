import { globby } from 'globby';
import { statSync, readFileSync } from 'fs';
import * as core from '@actions/core';
import { FileCov, ProjectCov } from './schema.js';
import { parseAnyCoverageContent } from './parsers/index.js';
import { enforceFileSizeLimits, enforceTotalSizeLimits } from './fs-limits.js';

export async function collectCoverage(
    patterns: string[], 
    maxBytesPerFile: number = 52428800, // 50 MB
    maxTotalBytes: number = 209715200,  // 200 MB
    strict: boolean = false
): Promise<ProjectCov> {
    const matches = await globby(patterns);
    const files = matches.slice(0, 1000); // Limit to 1000 files for safety
    const allFiles: FileCov[] = [];
    let totalSize = 0;

    for (const filePath of files) {
        try {
            // Check file size limits
            const stats = statSync(filePath);
            const fileSize = stats.size;
            
            try {
                enforceFileSizeLimits(fileSize, maxBytesPerFile);
                totalSize += fileSize;
                enforceTotalSizeLimits(totalSize, maxTotalBytes);
            } catch (error) {
                if (strict) {
                    throw error;
                } else {
                    core.warning(`Skipping file ${filePath}: ${error}`);
                    continue;
                }
            }

            const raw = readFileSync(filePath, 'utf8');
            
            // Auto-detect format and parse
            try {
                let hint: 'lcov' | 'cobertura' | undefined;
                
                if (filePath.endsWith('.info') || filePath.includes('lcov')) {
                    hint = 'lcov';
                } else if (filePath.endsWith('.xml') && raw.includes('coverage')) {
                    hint = 'cobertura';
                }
                
                const project = parseAnyCoverageContent(raw, hint);
                allFiles.push(...project.files);
                
            } catch (error) {
                if (strict) {
                    throw new Error(`Failed to parse coverage file ${filePath}: ${error}`);
                } else {
                    core.warning(`Failed to parse coverage file ${filePath}: ${error}`);
                }
            }
        } catch (error) {
            if (strict) {
                throw error;
            } else {
                core.warning(`Error processing file ${filePath}: ${error}`);
            }
        }
    }

    // Compute project totals
    const totals = {
        lines: { covered: 0, total: 0 },
        branches: { covered: 0, total: 0 },
        functions: { covered: 0, total: 0 }
    };

    for (const file of allFiles) {
        totals.lines.covered += file.lines.covered;
        totals.lines.total += file.lines.total;
        totals.branches.covered += file.branches.covered;
        totals.branches.total += file.branches.total;
        totals.functions.covered += file.functions.covered;
        totals.functions.total += file.functions.total;
    }

    return { files: allFiles, totals };
}
