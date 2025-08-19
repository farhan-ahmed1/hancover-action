export function enforceFileSizeLimits(fileSize: number, maxBytesPerFile: number): void {
    if (fileSize > maxBytesPerFile) {
        throw new Error(`File size exceeds the limit of ${maxBytesPerFile} bytes.`);
    }
}

export function enforceTotalSizeLimits(totalSize: number, maxTotalBytes: number): void {
    if (totalSize > maxTotalBytes) {
        throw new Error(`Total size exceeds the limit of ${maxTotalBytes} bytes.`);
    }
}