import { globby } from 'globby';
import { statSync, readFileSync } from 'fs';
import * as core from '@actions/core';
import { CoverageBundle } from './schema.js';
import { parseLcov } from './parsers/lcov.js';
import { parseCobertura } from './parsers/cobertura.js';
import { enforceFileSizeLimits, enforceTotalSizeLimits } from './fs-limits.js';

export async function collectCoverage(
    patterns: string[], 
    maxBytesPerFile: number = 52428800, // 50 MB
    maxTotalBytes: number = 209715200,  // 200 MB
    strict: boolean = false
): Promise<CoverageBundle> {
    const matches = await globby(patterns);
    const files = matches.slice(0, 1000); // Limit to 1000 files for safety
    const bundle: CoverageBundle = { files: [] };
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
            
            if (filePath.endsWith('.info') || filePath.includes('lcov')) {
                const parsedFile = parseLcov(raw, filePath);
                bundle.files.push(parsedFile);
            } else if (filePath.endsWith('.xml') && raw.includes('coverage')) {
                try {
                    const parsedFiles = parseCobertura(raw);
                    bundle.files.push(...parsedFiles.files);
                } catch (error) {
                    if (strict) {
                        throw new Error(`Failed to parse Cobertura file ${filePath}: ${error}`);
                    } else {
                        core.warning(`Failed to parse Cobertura file ${filePath}: ${error}`);
                    }
                }
            } else {
                if (strict) {
                    throw new Error(`Unsupported file format: ${filePath}`);
                } else {
                    core.warning(`Skipping unsupported file format: ${filePath}`);
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

    return bundle;
}
