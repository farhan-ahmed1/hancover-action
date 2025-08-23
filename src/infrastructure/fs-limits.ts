/**
 * Security and file size enforcement utilities
 */

const DEFAULT_MAX_BYTES_PER_FILE = 50 * 1024 * 1024; // 50MB
const DEFAULT_MAX_TOTAL_BYTES = 200 * 1024 * 1024; // 200MB

export function enforceFileSizeLimits(fileSize: number, maxBytesPerFile: number = DEFAULT_MAX_BYTES_PER_FILE): void {
    if (maxBytesPerFile < 0) {
        throw new Error('Maximum bytes per file must be non-negative');
    }
    if (fileSize < 0) {
        throw new Error('File size must be non-negative');
    }
    if (fileSize > maxBytesPerFile) {
        throw new Error(`File size (${formatBytes(fileSize)}) exceeds the limit of ${formatBytes(maxBytesPerFile)}.`);
    }
}

export function enforceTotalSizeLimits(totalSize: number, maxTotalBytes: number = DEFAULT_MAX_TOTAL_BYTES): void {
    if (maxTotalBytes < 0) {
        throw new Error('Maximum total bytes must be non-negative');
    }
    if (totalSize < 0) {
        throw new Error('Total size must be non-negative');
    }
    if (totalSize > maxTotalBytes) {
        throw new Error(`Total size (${formatBytes(totalSize)}) exceeds the limit of ${formatBytes(maxTotalBytes)}.`);
    }
}

/**
 * Enforce timeout limits based on elapsed time
 */
export function enforceTimeoutLimits(startTime: number, timeoutSeconds: number): void {
    if (timeoutSeconds < 0) {
        throw new Error('Timeout seconds must be non-negative');
    }
    if (startTime < 0) {
        throw new Error('Start time must be non-negative');
    }
    
    const elapsed = (Date.now() - startTime) / 1000;
    if (elapsed > timeoutSeconds) {
        throw new Error(`Operation timed out after ${timeoutSeconds}s`);
    }
}

/**
 * Validate XML content for security issues before parsing
 */
export function validateXmlSecurity(xmlContent: string): void {
    // Check for potentially dangerous XML constructs
    const dangerousPatterns = [
        /<!DOCTYPE[^>]*\[/i,  // DTD with internal subset
        /<!ENTITY/i,          // Entity declarations
        /SYSTEM\s+["']file:/i, // System entities with file:// protocol
        /SYSTEM\s+["']http/i,  // System entities with HTTP protocol
        /PUBLIC\s+["'][^"']*["']\s*["']file:/i, // Public entities with file:// protocol
    ];

    for (const pattern of dangerousPatterns) {
        if (pattern.test(xmlContent)) {
            throw new Error('XML content contains potentially dangerous constructs (DTD/Entities). This is blocked for security reasons.');
        }
    }

    // Check for excessive nesting (XML bomb protection)
    const nestingLevel = (xmlContent.match(/</g) || []).length;
    if (nestingLevel > 10000) {
        throw new Error('XML content has excessive nesting which may indicate a potential XML bomb attack.');
    }
}

function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}