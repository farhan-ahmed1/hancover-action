import { readFileSync } from 'fs';
import { FileCov } from '../schema.js';

export function parseLCOV(data: string): FileCov[] {
    const files: FileCov[] = [];
    let currentFile: FileCov | null = null;

    const lines = data.split('\n');
    for (const line of lines) {
        if (line.startsWith('SF:')) {
            if (currentFile) {
                files.push(currentFile);
            }
            currentFile = {
                path: line.substring(3).trim(),
                lines: [],
                summary: { linesCovered: 0, linesTotal: 0 }
            };
        } else if (line.startsWith('DA:') && currentFile) {
            const [lineInfo, hits] = line.substring(3).split(',');
            const lineNumber = parseInt(lineInfo, 10);
            const hitCount = parseInt(hits, 10);
            currentFile.lines.push({ line: lineNumber, hits: hitCount });
            currentFile.summary.linesTotal++;
            if (hitCount > 0) {
                currentFile.summary.linesCovered++;
            }
        }
    }

    if (currentFile) {
        files.push(currentFile);
    }

    return files;
}

// Read LCOV file from disk and parse it
export function parseLcovFile(filePath: string): FileCov[] {
    try {
        const data = readFileSync(filePath, 'utf8');
        return parseLCOV(data);
    } catch (error) {
        throw new Error(`Failed to read LCOV file ${filePath}: ${error}`);
    }
}

// Compatibility wrapper used by normalize.ts
export function parseLcov(filePathOrRaw: string, pathHint?: string): FileCov {
    let files: FileCov[];
    
    // If it looks like a file path, read from disk
    if (filePathOrRaw.includes('/') || filePathOrRaw.endsWith('.info') || filePathOrRaw.endsWith('.lcov')) {
        try {
            files = parseLcovFile(filePathOrRaw);
        } catch {
            // Fallback to treating as raw data
            files = parseLCOV(filePathOrRaw);
        }
    } else {
        // Treat as raw LCOV data
        files = parseLCOV(filePathOrRaw);
    }
    
    if (files.length > 0) return files[0];
    return { path: pathHint ?? 'unknown', lines: [], summary: { linesCovered: 0, linesTotal: 0 } };
}