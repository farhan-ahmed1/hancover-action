export function generateBadgeUrl(label: string, message: string, color: string = 'blue'): string {
    return `https://img.shields.io/badge/${encodeURIComponent(label)}-${encodeURIComponent(message)}-${color}`;
}

export function generateCoverageBadge(coverage: number): string {
    const color = getColorForPercentage(coverage);
    return generateBadgeUrl('coverage', `${coverage.toFixed(1)}%`, color);
}

export function generateBuildBadge(status: string): string {
    const color = status === 'passing' ? 'brightgreen' : 'red';
    return generateBadgeUrl('build', status, color);
}

export function generateDeltaBadge(delta: number): string {
    const isPositive = delta >= 0;
    const prefix = isPositive ? '+' : '';
    const value = `${prefix}${delta.toFixed(1)}%`;
    const color = isPositive ? 'brightgreen' : 'red';
    return generateBadgeUrl('Δ coverage', value, color);
}

export function createShieldsBadge(label: string, message: string, color: string): string {
    const encodedLabel = encodeURIComponent(label);
    const encodedMessage = encodeURIComponent(message);
    return `https://img.shields.io/badge/${encodedLabel}-${encodedMessage}-${color}`;
}

export function getColorForPercentage(percentage: number): string {
    if (percentage >= 90) return 'brightgreen';
    if (percentage >= 80) return 'green';
    if (percentage >= 70) return 'yellowgreen';
    if (percentage >= 60) return 'yellow';
    if (percentage >= 50) return 'orange';
    return 'red';
}

export function getHealthIcon(percentage: number, threshold: number = 50): string {
    return percentage >= threshold ? '✅' : '❌';
}