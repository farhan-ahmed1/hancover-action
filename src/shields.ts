import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';

export interface CoverageData {
    coverage: number;
    timestamp: string;
    branch: string;
    commit?: string;
}

/**
 * Reads main branch coverage from a local JSON file
 * @param filePath Path to the coverage data JSON file
 * @returns Coverage percentage or null if not available
 */
export function readMainBranchCoverage(filePath: string): number | null {
    try {
        if (!fs.existsSync(filePath)) {
            core.info(`Coverage data file not found: ${filePath}`);
            return null;
        }

        const data = fs.readFileSync(filePath, 'utf8');
        const coverageData = JSON.parse(data) as CoverageData;
        
        if (typeof coverageData.coverage === 'number') {
            core.info(`Main branch coverage from ${filePath}: ${coverageData.coverage.toFixed(1)}% (updated: ${coverageData.timestamp})`);
            return coverageData.coverage;
        } else {
            core.warning('Invalid coverage data format in JSON file');
            return null;
        }
    } catch (error) {
        core.warning(`Error reading coverage data file: ${error}`);
        return null;
    }
}

/**
 * Writes coverage data to a local JSON file
 * @param filePath Path to write the coverage data
 * @param coverage Coverage percentage
 * @param branch Branch name
 * @param commit Commit hash (optional)
 */
export function writeCoverageData(filePath: string, coverage: number, branch: string = 'main', commit?: string): void {
    try {
        const coverageData: CoverageData = {
            coverage,
            timestamp: new Date().toISOString(),
            branch,
            commit
        };

        // Ensure directory exists
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        fs.writeFileSync(filePath, JSON.stringify(coverageData, null, 2));
        core.info(`Coverage data written to: ${filePath} (${coverage.toFixed(1)}%)`);
    } catch (error) {
        core.warning(`Failed to write coverage data: ${error}`);
    }
}

/**
 * Generates a changes badge showing coverage delta with two-color design
 * @param currentCoverage Current PR coverage
 * @param mainCoverage Main branch coverage
 * @returns Badge URL
 */
export function generateChangesBadge(currentCoverage: number, mainCoverage: number): string {
    const delta = currentCoverage - mainCoverage;
    const prefix = delta >= 0 ? '+' : '';
    const value = `${prefix}${delta.toFixed(1)}%`;
    const valueColor = delta >= 0 ? 'brightgreen' : 'red';
    
    // Use two-color badge format: label color (lightgrey) and value color (based on delta)
    const encodedLabel = encodeURIComponent('changes');
    const encodedValue = encodeURIComponent(value);
    return `https://img.shields.io/badge/${encodedLabel}-${encodedValue}-lightgrey?labelColor=lightgrey&color=${valueColor}`;
}

/**
 * Generates a badge URL
 * @param label Badge label
 * @param message Badge message
 * @param color Badge color
 * @returns Badge URL
 */
export function generateBadgeUrl(label: string, message: string, color: string): string {
    const encodedLabel = encodeURIComponent(label);
    const encodedMessage = encodeURIComponent(message);
    return `https://img.shields.io/badge/${encodedLabel}-${encodedMessage}-${color}`;
}
