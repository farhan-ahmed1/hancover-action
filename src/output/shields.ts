/**
 * Generates a changes badge showing coverage delta
 * @param currentCoverage Current PR coverage
 * @param mainCoverage Main branch coverage
 * @returns Badge URL
 */
export function generateChangesBadge(currentCoverage: number, mainCoverage: number): string {
    const delta = currentCoverage - mainCoverage;
    const prefix = delta >= 0 ? '+' : '';
    const value = `${prefix}${delta.toFixed(1)}%`;
    const color = delta >= 0 ? 'brightgreen' : 'red';
    
    return generateBadgeUrl('changes', value, color);
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
