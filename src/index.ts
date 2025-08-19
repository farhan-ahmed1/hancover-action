import * as core from '@actions/core';
import { runEnhancedCoverage } from './enhanced.js';

async function run() {
    try {
        await runEnhancedCoverage();
    } catch (e: any) {
        core.setFailed(e?.message ?? String(e));
    }
}

run();
