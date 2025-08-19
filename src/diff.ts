import { execSync } from 'child_process';
import * as core from '@actions/core';

export async function computeDiff(baseRef?: string): Promise<Record<string, Set<number>>> {
    const diffMap: Record<string, Set<number>> = {};
    
    try {
        // Default to comparing with the base branch if no baseRef provided
        const ref = baseRef || 'HEAD~1';
        
        // Run git diff to get changed lines
        const diffOutput = execSync(`git diff --unified=0 ${ref}..HEAD`, { 
            encoding: 'utf8',
            cwd: process.cwd(),
            maxBuffer: 1024 * 1024 * 50, // 50MB buffer limit (increased)
            timeout: 60000 // 60 second timeout (increased)
        });
        
        const lines = diffOutput.split('\n');
        let currentFile: string | null = null;
        
        for (const line of lines) {
            // Parse file headers (e.g., "--- a/src/file.ts", "+++ b/src/file.ts")
            if (line.startsWith('+++')) {
                const match = line.match(/^\+\+\+ b\/(.+)$/);
                if (match) {
                    currentFile = match[1];
                    if (!diffMap[currentFile]) {
                        diffMap[currentFile] = new Set<number>();
                    }
                }
            }
            // Parse hunk headers (e.g., "@@ -1,3 +1,4 @@")
            else if (line.startsWith('@@') && currentFile) {
                const hunkMatch = line.match(/@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
                if (hunkMatch) {
                    const newStart = parseInt(hunkMatch[3], 10);
                    const newCount = hunkMatch[4] ? parseInt(hunkMatch[4], 10) : 1;
                    
                    // Add all lines in the changed range
                    for (let i = 0; i < newCount; i++) {
                        diffMap[currentFile].add(newStart + i);
                    }
                }
            }
        }
        
        return diffMap;
    } catch (error) {
        // If git diff fails (e.g., no git repo, no commits, ENOBUFS), return empty diff
        if (error instanceof Error) {
            if (error.message.includes('ENOBUFS')) {
                core.warning('Git diff output too large (ENOBUFS). Skipping diff coverage calculation.');
            } else {
                core.warning(`Failed to compute diff: ${error.message}`);
            }
        } else {
            core.warning(`Failed to compute diff: ${error}`);
        }
        return {};
    }
}
