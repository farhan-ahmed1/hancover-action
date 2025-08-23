/**
 * Progress reporting utilities for long-running operations
 */

import * as core from '@actions/core';

export interface ProgressReporter {
    // eslint-disable-next-line no-unused-vars
    report(stage: string, percentage: number, details?: string): void;
    // eslint-disable-next-line no-unused-vars
    start(totalSteps: number, operation: string): void;
    // eslint-disable-next-line no-unused-vars
    step(completedSteps: number, currentStep?: string): void;
    // eslint-disable-next-line no-unused-vars
    finish(message?: string): void;
}

/**
 * Core-based progress reporter that logs to GitHub Actions
 */
export class CoreProgressReporter implements ProgressReporter {
    private totalSteps = 0;
    private operation = '';
    private lastReported = 0;
    private readonly reportThreshold = 5; // Report every 5% change

    start(totalSteps: number, operation: string): void {
        this.totalSteps = totalSteps;
        this.operation = operation;
        this.lastReported = 0;
        core.info(`🚀 Starting ${operation}...`);
    }

    step(completedSteps: number, currentStep?: string): void {
        if (this.totalSteps === 0) return;
        
        const percentage = Math.min((completedSteps / this.totalSteps) * 100, 100);
        const details = currentStep ? ` - ${currentStep}` : '';
        
        // Only report if significant progress made
        if (percentage - this.lastReported >= this.reportThreshold || percentage === 100) {
            this.report(`${this.operation} Progress`, percentage, details);
            this.lastReported = percentage;
        }
    }

    report(stage: string, percentage: number, details = ''): void {
        const progressBar = this.createProgressBar(percentage);
        const msg = `${stage}: ${progressBar} ${percentage.toFixed(1)}%${details}`;
        
        if (percentage === 100) {
            core.info(`✅ ${msg}`);
        } else {
            core.info(`⏳ ${msg}`);
        }
    }

    finish(message = 'Operation completed successfully'): void {
        core.info(`🎉 ${message}`);
    }

    private createProgressBar(percentage: number, length = 20): string {
        const filled = Math.round((percentage / 100) * length);
        const empty = length - filled;
        return '█'.repeat(filled) + '░'.repeat(empty);
    }
}

/**
 * Null progress reporter (no-op) for silent operation
 */
export class NullProgressReporter implements ProgressReporter {
    // eslint-disable-next-line no-unused-vars
    report(stage: string, percentage: number, details?: string): void {
        // No-op
    }

    // eslint-disable-next-line no-unused-vars
    start(totalSteps: number, operation: string): void {
        // No-op
    }

    // eslint-disable-next-line no-unused-vars
    step(completedSteps: number, currentStep?: string): void {
        // No-op
    }

    // eslint-disable-next-line no-unused-vars
    finish(message?: string): void {
        // No-op
    }
}

/**
 * File processing progress tracker
 */
export class FileProcessingTracker {
    private readonly reporter: ProgressReporter;
    private totalFiles = 0;
    private processedFiles = 0;
    private totalBytes = 0;
    private processedBytes = 0;

    constructor(reporter: ProgressReporter) {
        this.reporter = reporter;
    }

    startFileProcessing(files: Array<{ path: string; size: number }>): void {
        this.totalFiles = files.length;
        this.processedFiles = 0;
        this.totalBytes = files.reduce((sum, f) => sum + f.size, 0);
        this.processedBytes = 0;

        const totalSize = this.formatBytes(this.totalBytes);
        this.reporter.start(this.totalFiles, `Processing ${this.totalFiles} coverage files (${totalSize})`);
    }

    updateFileProgress(fileName: string, bytesProcessed: number, fileSize: number): void {
        // Update byte-level progress for current file
        const filePercentage = (bytesProcessed / fileSize) * 100;
        this.reporter.report(
            `Processing ${fileName}`, 
            filePercentage, 
            ` (${this.formatBytes(bytesProcessed)}/${this.formatBytes(fileSize)})`
        );
    }

    completeFile(fileName: string, fileSize: number): void {
        this.processedFiles++;
        this.processedBytes += fileSize;
        
        const overallPercentage = (this.processedFiles / this.totalFiles) * 100;
        this.reporter.step(
            this.processedFiles, 
            `Completed ${fileName} (${this.formatBytes(fileSize)})`
        );
        
        // Report overall progress
        this.reporter.report(
            'Overall Progress',
            overallPercentage,
            ` - ${this.processedFiles}/${this.totalFiles} files, ${this.formatBytes(this.processedBytes)}/${this.formatBytes(this.totalBytes)}`
        );
    }

    finish(): void {
        this.reporter.finish(`Successfully processed ${this.totalFiles} files (${this.formatBytes(this.totalBytes)})`);
    }

    private formatBytes(bytes: number): string {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
}

/**
 * Global progress reporter instance
 */
export const globalProgressReporter = new CoreProgressReporter();

/**
 * Create a file processing tracker with the global reporter
 */
export function createFileTracker(): FileProcessingTracker {
    return new FileProcessingTracker(globalProgressReporter);
}
