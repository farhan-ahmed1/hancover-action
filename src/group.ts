import { CoverageBundle, FileCov, GroupsConfig } from './schema.js';

export type GroupSummary = {
    name: string;
    files: FileCov[];
    coveragePct: number;
    linesCovered: number;
    linesTotal: number;
};

export function groupCoverage(bundle: CoverageBundle, groups?: GroupsConfig): Map<string, FileCov[]> {
    const groupedCoverage = new Map<string, FileCov[]>();

    // Auto-grouping logic: derive package from first path segment
    for (const file of bundle.files) {
        let packageName = 'root';
        
        // Extract package name from path (e.g., "apps/web/src/file.ts" → "apps")
        const pathSegments = file.path.split('/').filter(segment => segment.length > 0);
        if (pathSegments.length > 0) {
            packageName = pathSegments[0];
        }
        
        if (!groupedCoverage.has(packageName)) {
            groupedCoverage.set(packageName, []);
        }
        groupedCoverage.get(packageName)?.push(file);
        
        // Set package info on the file for reference
        file.package = packageName;
    }

    // User-defined grouping logic (overrides auto-grouping)
    if (groups && groups.length > 0) {
        // Clear auto groups and rebuild with user-defined groups
        groupedCoverage.clear();
        
        for (const group of groups) {
            const filesInGroup: FileCov[] = [];
            for (const file of bundle.files) {
                if (matchesGroup(file.path, group)) {
                    filesInGroup.push(file);
                    file.package = group.name;
                }
            }
            if (filesInGroup.length > 0) {
                groupedCoverage.set(group.name, filesInGroup);
            }
        }
        
        // Add ungrouped files to a "other" group
        const ungroupedFiles = bundle.files.filter(file => !file.package || file.package === 'root');
        if (ungroupedFiles.length > 0) {
            groupedCoverage.set('other', ungroupedFiles);
        }
    }

    return groupedCoverage;
}

export function computeGroupSummaries(groupedCoverage: Map<string, FileCov[]>): GroupSummary[] {
    const summaries: GroupSummary[] = [];
    
    for (const [name, files] of groupedCoverage.entries()) {
        let totalLinesCovered = 0;
        let totalLines = 0;
        
        for (const file of files) {
            totalLinesCovered += file.summary.linesCovered;
            totalLines += file.summary.linesTotal;
        }
        
        const coveragePct = totalLines > 0 ? Math.round((totalLinesCovered / totalLines) * 10000) / 100 : 0;
        
        summaries.push({
            name,
            files,
            coveragePct,
            linesCovered: totalLinesCovered,
            linesTotal: totalLines
        });
    }
    
    // Sort by coverage percentage (descending)
    return summaries.sort((a, b) => b.coveragePct - a.coveragePct);
}

function matchesGroup(filePath: string, group: { name: string; include: string | string[]; exclude?: string | string[] }): boolean {
    const includes = Array.isArray(group.include) ? group.include : [group.include];
    const excludes = group.exclude ? (Array.isArray(group.exclude) ? group.exclude : [group.exclude]) : [];

    // Use glob-like matching for better pattern support
    const isIncluded = includes.some(includePattern => {
        // Convert simple glob patterns to regex
        const regexPattern = includePattern
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.');
        const regex = new RegExp(`^${regexPattern}$`);
        return regex.test(filePath) || filePath.includes(includePattern);
    });
    
    const isExcluded = excludes.some(excludePattern => {
        const regexPattern = excludePattern
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.');
        const regex = new RegExp(`^${regexPattern}$`);
        return regex.test(filePath) || filePath.includes(excludePattern);
    });

    return isIncluded && !isExcluded;
}