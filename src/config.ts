import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

export type GroupRule = { 
  name: string; 
  patterns: string[]; 
  exclude?: string[]; 
};

export type EcosystemType = 'node' | 'java' | 'python' | 'dotnet' | 'go' | 'ruby' | 'generic';

export type EcosystemConfig = {
    type: EcosystemType;
    recommendedThresholds: {
        total: number;
        changes: number;
    };
    suggestedGroups: GroupRule[];
};

export type Config = {
  groups?: GroupRule[];
  fallback?: { 
    smartDepth?: 'auto' | 'top' | 'two'; 
    promoteThreshold?: number; 
  };
  ui?: { 
    expandFilesFor?: string[]; 
    maxDeltaRows?: number; 
    minPassThreshold?: number; 
  };
};

// Legacy default config for backwards compatibility
const DEFAULT_CONFIG: Required<Config> = {
    groups: [],
    fallback: {
        smartDepth: 'auto',
        promoteThreshold: 0.8
    },
    ui: {
        expandFilesFor: [],
        maxDeltaRows: 10,
        minPassThreshold: 50
    }
};

export function loadConfig(cwd = process.cwd()): Required<Config> {
    const configPath = path.join(cwd, '.coverage-report.json');
    
    // Detect ecosystem for smart defaults
    const ecosystem = detectEcosystem([], cwd);
    core.debug(`Detected ecosystem: ${ecosystem.type}`);

    // Create ecosystem-aware defaults
    const ecosystemDefaults: Required<Config> = {
        groups: ecosystem.suggestedGroups,
        fallback: {
            smartDepth: 'auto',
            promoteThreshold: 0.8
        },
        ui: {
            expandFilesFor: ecosystem.suggestedGroups.map(g => g.name),
            maxDeltaRows: 10,
            minPassThreshold: ecosystem.recommendedThresholds.total
        }
    };

    try {
        if (!fs.existsSync(configPath)) {
            core.debug(`No .coverage-report.json found, using smart defaults for ${ecosystem.type} ecosystem`);
            return ecosystemDefaults;
        }

        const rawConfig = JSON.parse(fs.readFileSync(configPath, 'utf8')) as Config;
        core.info(`Loaded config from ${configPath}`);

        // Merge with ecosystem-aware defaults (instead of generic defaults)
        const config: Required<Config> = {
            groups: rawConfig.groups || ecosystemDefaults.groups,
            fallback: {
                ...ecosystemDefaults.fallback,
                ...rawConfig.fallback
            },
            ui: {
                ...ecosystemDefaults.ui,
                ...rawConfig.ui
            }
        };

        core.debug(`Config: ${JSON.stringify(config, null, 2)}`);
        return config;

    } catch (error) {
        core.warning(`Failed to load config from ${configPath}: ${error}. Using ecosystem defaults for ${ecosystem.type}.`);
        return ecosystemDefaults;
    }
}

/**
 * Check if a file path matches any of the given glob patterns
 * For now, we'll use simple glob matching with * and **
 */
export function matchesPatterns(filePath: string, patterns: string[]): boolean {
    const normalizedPath = path.posix.normalize(filePath);

    return patterns.some(pattern => {
        // Convert simple glob pattern to regex
        let regexPattern = pattern
            .replace(/\*\*/g, '§DOUBLE_STAR§')  // Temporary placeholder
            .replace(/\*/g, '[^/]*')            // * matches any characters except /
            .replace(/§DOUBLE_STAR§/g, '.*')    // ** matches any number of directories
            .replace(/\?/g, '[^/]');            // ? matches any single character except /

        const regex = new RegExp(`^${regexPattern}$`);
        const matches = regex.test(normalizedPath);
        
        return matches;
    });
}

/**
 * Detect the ecosystem type based on project files and structure
 */
export function detectEcosystem(files: string[] = [], cwd = process.cwd()): EcosystemConfig {
    // Check for ecosystem indicator files
    const hasPackageJson = fs.existsSync(path.join(cwd, 'package.json'));
    const hasPomXml = fs.existsSync(path.join(cwd, 'pom.xml'));
    const hasGradleBuild = fs.existsSync(path.join(cwd, 'build.gradle')) || fs.existsSync(path.join(cwd, 'build.gradle.kts'));
    const hasPyprojectToml = fs.existsSync(path.join(cwd, 'pyproject.toml'));
    const hasSetupPy = fs.existsSync(path.join(cwd, 'setup.py'));
    const hasRequirementsTxt = fs.existsSync(path.join(cwd, 'requirements.txt'));
    const hasCsproj = fs.existsSync(path.join(cwd, '*.csproj')) || files.some(f => f.endsWith('.csproj'));
    const hasGoMod = fs.existsSync(path.join(cwd, 'go.mod'));
    const hasGemfile = fs.existsSync(path.join(cwd, 'Gemfile'));

    // Determine ecosystem type based on priority
    let type: EcosystemType = 'generic';
    
    if (hasPackageJson) {
        type = 'node';
    } else if (hasPomXml || hasGradleBuild) {
        type = 'java';
    } else if (hasPyprojectToml || hasSetupPy || hasRequirementsTxt) {
        type = 'python';
    } else if (hasCsproj) {
        type = 'dotnet';
    } else if (hasGoMod) {
        type = 'go';
    } else if (hasGemfile) {
        type = 'ruby';
    }

    return {
        type,
        recommendedThresholds: getRecommendedThresholds(type),
        suggestedGroups: getSuggestedGroups(type)
    };
}

/**
 * Get recommended thresholds based on ecosystem type
 */
function getRecommendedThresholds(type: EcosystemType): { total: number; changes: number } {
    const thresholds = {
        node: { total: 80, changes: 85 },
        java: { total: 70, changes: 80 },
        python: { total: 85, changes: 90 },
        dotnet: { total: 75, changes: 80 },
        go: { total: 80, changes: 85 },
        ruby: { total: 80, changes: 85 },
        generic: { total: 50, changes: 60 }
    };
    
    return thresholds[type];
}

/**
 * Get suggested grouping patterns based on ecosystem type
 */
function getSuggestedGroups(type: EcosystemType): GroupRule[] {
    const groupingPatterns: Record<EcosystemType, GroupRule[]> = {
        node: [
            { name: 'src/components', patterns: ['src/components/**'] },
            { name: 'src/utils', patterns: ['src/utils/**', 'src/lib/**'] },
            { name: 'src/services', patterns: ['src/services/**', 'src/api/**'] },
            { name: 'src', patterns: ['src/**'], exclude: ['src/components/**', 'src/utils/**', 'src/lib/**', 'src/services/**', 'src/api/**'] }
        ],
        java: [
            { name: 'main/java', patterns: ['src/main/java/**'] },
            { name: 'main/resources', patterns: ['src/main/resources/**'] },
            { name: 'test', patterns: ['src/test/**'] }
        ],
        python: [
            { name: 'src', patterns: ['src/**', '*.py'] },
            { name: 'tests', patterns: ['tests/**', 'test/**'] },
            { name: 'package', patterns: ['**/**.py'], exclude: ['src/**', 'tests/**', 'test/**'] }
        ],
        dotnet: [
            { name: 'Controllers', patterns: ['**/Controllers/**'] },
            { name: 'Models', patterns: ['**/Models/**'] },
            { name: 'Services', patterns: ['**/Services/**'] },
            { name: 'Core', patterns: ['**/*.cs'], exclude: ['**/Controllers/**', '**/Models/**', '**/Services/**'] }
        ],
        go: [
            { name: 'cmd', patterns: ['cmd/**'] },
            { name: 'internal', patterns: ['internal/**'] },
            { name: 'pkg', patterns: ['pkg/**'] },
            { name: 'root', patterns: ['*.go'] }
        ],
        ruby: [
            { name: 'app', patterns: ['app/**'] },
            { name: 'lib', patterns: ['lib/**'] },
            { name: 'config', patterns: ['config/**'] },
            { name: 'spec', patterns: ['spec/**'] }
        ],
        generic: []
    };
    
    return groupingPatterns[type];
}
