export function generateBadgeUrl(label: string, message: string, color: string = 'blue'): string {
    return `https://img.shields.io/badge/${encodeURIComponent(label)}-${encodeURIComponent(message)}-${color}`;
}

export function generateCoverageBadge(coverage: number): string {
    const color = coverage >= 80 ? 'brightgreen' : coverage >= 60 ? 'yellow' : 'red';
    return generateBadgeUrl('coverage', `${coverage}%`, color);
}

export function generateBuildBadge(status: string): string {
    const color = status === 'passing' ? 'brightgreen' : 'red';
    return generateBadgeUrl('build', status, color);
}