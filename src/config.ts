import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

export type GroupRule = { 
  name: string; 
  patterns: string[]; 
  exclude?: string[]; 
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

    try {
        if (!fs.existsSync(configPath)) {
            core.debug('No .coverage-report.json found, using smart defaults');
            return DEFAULT_CONFIG;
        }

        const rawConfig = JSON.parse(fs.readFileSync(configPath, 'utf8')) as Config;
        core.info(`Loaded config from ${configPath}`);

        // Merge with defaults
        const config: Required<Config> = {
            groups: rawConfig.groups || DEFAULT_CONFIG.groups,
            fallback: {
                ...DEFAULT_CONFIG.fallback,
                ...rawConfig.fallback
            },
            ui: {
                ...DEFAULT_CONFIG.ui,
                ...rawConfig.ui
            }
        };

        core.debug(`Config: ${JSON.stringify(config, null, 2)}`);
        return config;

    } catch (error) {
        core.warning(`Failed to load config from ${configPath}: ${error}. Using defaults.`);
        return DEFAULT_CONFIG;
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
