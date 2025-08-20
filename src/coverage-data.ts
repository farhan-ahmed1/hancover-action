import * as core from '@actions/core';
import * as github from '@actions/github';

export interface CoverageData {
    coverage: number;
    timestamp: string;
    branch: string;
    commit: string;
}

/**
 * Get coverage data from GitHub Gist
 */
export async function getCoverageData(): Promise<number | null> {
    try {
        const gistId = core.getInput('gist-id');
        const token = core.getInput('github-token') || process.env.GITHUB_TOKEN;
        
        if (!gistId) {
            core.info('No gist-id provided, skipping baseline coverage fetch');
            return null;
        }
        
        if (!token) {
            core.warning('No GitHub token provided, cannot fetch from gist');
            return null;
        }

        core.info(`Fetching coverage data from gist: ${gistId}`);
        const coverage = await fetchCoverageFromGist(token, gistId);
        
        if (coverage === null) {
            core.warning('No coverage data found in gist');
        }
        
        return coverage;
    } catch (error) {
        core.warning(`Failed to get coverage data from gist: ${error}`);
        return null;
    }
}

/**
 * Save coverage data to GitHub Gist only
 */
export async function saveCoverageData(coverage: number): Promise<void> {
    const gistId = core.getInput('gist-id');
    const token = core.getInput('github-token') || process.env.GITHUB_TOKEN;
    
    if (!gistId) {
        core.info('No gist-id provided, skipping coverage data save');
        return;
    }
    
    if (!token) {
        core.warning('No GitHub token provided, cannot save to gist');
        return;
    }

    const data: CoverageData = {
        coverage,
        timestamp: new Date().toISOString(),
        branch: github.context.ref.replace('refs/heads/', ''),
        commit: github.context.sha
    };

    try {
        core.info(`Updating coverage data in gist: ${gistId}`);
        await updateCoverageInGist(token, gistId, data);
        core.info(`Coverage data saved: ${coverage.toFixed(1)}%`);
    } catch (error) {
        core.error(`Failed to save coverage data to gist: ${error}`);
        throw error;
    }
}

/**
 * Fetch coverage data from GitHub Gist
 */
async function fetchCoverageFromGist(token: string, gistId: string): Promise<number | null> {
    try {
        const octokit = github.getOctokit(token);

        const { data } = await octokit.rest.gists.get({
            gist_id: gistId
        });

        const coverageFile = data.files?.['coverage.json'];
        if (coverageFile?.content) {
            const coverageData: CoverageData = JSON.parse(coverageFile.content);
            core.info(`Fetched coverage from gist: ${coverageData.coverage.toFixed(1)}%`);
            return coverageData.coverage;
        }

        return null;
    } catch (error) {
        core.debug(`Failed to fetch coverage from gist: ${error}`);
        return null;
    }
}

/**
 * Update coverage data in GitHub Gist
 */
async function updateCoverageInGist(token: string, gistId: string, data: CoverageData): Promise<void> {
    try {
        const octokit = github.getOctokit(token);

        await octokit.rest.gists.update({
            gist_id: gistId,
            files: {
                'coverage.json': {
                    content: JSON.stringify(data, null, 2)
                },
                'coverage-badge.json': {
                    content: JSON.stringify({
                        schemaVersion: 1,
                        label: 'coverage',
                        message: `${data.coverage.toFixed(1)}%`,
                        color: getColorForPercentage(data.coverage)
                    }, null, 2)
                }
            }
        });

        core.info(`Coverage data updated in gist: ${gistId}`);
    } catch (error) {
        core.error(`Failed to update coverage in gist: ${error}`);
        throw error;
    }
}

function getColorForPercentage(percentage: number): string {
    if (percentage >= 90) return 'brightgreen';
    if (percentage >= 80) return 'green';
    if (percentage >= 70) return 'yellowgreen';
    if (percentage >= 60) return 'yellow';
    if (percentage >= 50) return 'orange';
    return 'red';
}
