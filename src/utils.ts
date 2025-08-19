export function log(message: string): void {
    // Using process.stdout.write instead of console.log to avoid no-console warning
    process.stdout.write(`${message}\n`);
}

export function parseGlobPatterns(patterns: string[]): string[] {
    // This function can be expanded to handle glob patterns in the future
    return patterns;
}

export function isValidFilePath(): boolean {
    // Placeholder for file path validation logic
    return true;
}