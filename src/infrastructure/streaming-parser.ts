/**
 * Streaming XML parser utilities for handling large coverage files
 * without loading them entirely into memory
 */

import { createReadStream } from 'fs';
import { Transform } from 'stream';
import * as core from '@actions/core';
import { validateXmlSecurity } from './fs-limits.js';

export interface StreamingProgress {
    bytesProcessed: number;
    totalBytes: number;
    percentage: number;
    stage: string;
}

// eslint-disable-next-line no-unused-vars
export type ProgressCallback = (progressInfo: StreamingProgress) => void;

/**
 * Options for streaming XML parsing
 */
export interface StreamingParseOptions {
    timeoutMs?: number;
    chunkSize?: number;
    onProgress?: ProgressCallback;
    maxMemoryUsage?: number; // Maximum memory usage before forcing streaming mode
}

/**
 * Check if a file should be parsed using streaming mode based on size
 */
export function shouldUseStreaming(fileSizeBytes: number, options: StreamingParseOptions = {}): boolean {
    const maxMemoryUsage = options.maxMemoryUsage ?? 10 * 1024 * 1024; // 10MB default
    return fileSizeBytes > maxMemoryUsage;
}

/**
 * Streaming XML chunk processor that accumulates valid XML fragments
 */
class XMLChunkProcessor extends Transform {
    private buffer = '';
    private elementStack: string[] = [];
    private inElement = false;
    private currentElement = '';
    private onProgress?: ProgressCallback;
    private bytesProcessed = 0;
    private totalBytes: number;
    private lastProgressUpdate = 0;

    constructor(totalBytes: number, onProgress?: ProgressCallback) {
        super({ objectMode: true });
        this.totalBytes = totalBytes;
        this.onProgress = onProgress;
    }

    _transform(chunk: any, encoding: BufferEncoding, callback: Function) {
        try {
            this.buffer += chunk.toString();
            this.bytesProcessed += chunk.length;

            // Report progress every 1MB or 5% of file, whichever is smaller
            const progressThreshold = Math.min(1024 * 1024, this.totalBytes * 0.05);
            if (this.bytesProcessed - this.lastProgressUpdate > progressThreshold) {
                this.reportProgress('Parsing XML content');
                this.lastProgressUpdate = this.bytesProcessed;
            }

            // Process complete XML elements
            this.processBuffer();
            callback();
        } catch (error) {
            callback(error);
        }
    }

    _flush(callback: Function) {
        try {
            // Process any remaining buffer content
            this.processBuffer(true);
            this.reportProgress('Parsing complete');
            callback();
        } catch (error) {
            callback(error);
        }
    }

    private processBuffer(final = false) {
        // Simple XML element boundary detection
        // This is a basic implementation - for production might want a more sophisticated parser
        let startIndex = 0;
        
        while (true) {
            const elementStart = this.buffer.indexOf('<', startIndex);
            if (elementStart === -1) break;

            const elementEnd = this.buffer.indexOf('>', elementStart);
            if (elementEnd === -1 && !final) break; // Wait for complete element

            if (elementEnd !== -1) {
                const element = this.buffer.substring(elementStart, elementEnd + 1);
                this.processXMLElement(element);
                startIndex = elementEnd + 1;
            } else {
                break;
            }
        }

        // Keep unprocessed content in buffer
        if (startIndex > 0) {
            this.buffer = this.buffer.substring(startIndex);
        }
    }

    private processXMLElement(element: string) {
        // Emit complete XML fragments for downstream processing
        this.push(element);
    }

    private reportProgress(stage: string) {
        if (this.onProgress) {
            const percentage = Math.min((this.bytesProcessed / this.totalBytes) * 100, 100);
            this.onProgress({
                bytesProcessed: this.bytesProcessed,
                totalBytes: this.totalBytes,
                percentage,
                stage
            });
        }
    }
}

/**
 * Stream-based XML content reader with progress tracking
 */
export async function streamXMLContent(
    filePath: string, 
    totalBytes: number,
    options: StreamingParseOptions = {}
): Promise<string> {
    const { timeoutMs = 120000, chunkSize = 64 * 1024, onProgress } = options;

    return new Promise((resolve, reject) => {
        let content = '';
        let timeoutId: NodeJS.Timeout | undefined;
        
        // Set up timeout
        if (timeoutMs > 0) {
            timeoutId = setTimeout(() => {
                reject(new Error(`Streaming XML read timed out after ${timeoutMs}ms for file: ${filePath}`));
            }, timeoutMs);
        }

        const cleanup = () => {
            if (timeoutId) {
                clearTimeout(timeoutId);
            }
        };

        try {
            const readStream = createReadStream(filePath, { 
                encoding: 'utf8',
                highWaterMark: chunkSize 
            });

            const processor = new XMLChunkProcessor(totalBytes, onProgress);

            // Collect processed chunks
            processor.on('data', (chunk) => {
                content += chunk;
            });

            processor.on('end', () => {
                cleanup();
                resolve(content);
            });

            processor.on('error', (error) => {
                cleanup();
                reject(new Error(`Failed to stream XML content from ${filePath}: ${error.message}`));
            });

            readStream.on('error', (error) => {
                cleanup();
                reject(new Error(`Failed to read file ${filePath}: ${error.message}`));
            });

            // Connect streams
            readStream.pipe(processor);

        } catch (error) {
            cleanup();
            reject(error);
        }
    });
}

/**
 * Enhanced XML parsing with streaming support and progress reporting
 */
export async function parseXMLWithStreaming(
    filePath: string,
    fileSizeBytes: number,
    options: StreamingParseOptions = {}
): Promise<string> {
    const useStreaming = shouldUseStreaming(fileSizeBytes, options);
    
    if (options.onProgress) {
        options.onProgress({
            bytesProcessed: 0,
            totalBytes: fileSizeBytes,
            percentage: 0,
            stage: useStreaming ? 'Starting streaming parse' : 'Starting standard parse'
        });
    }

    let xmlContent: string;

    if (useStreaming) {
        core.info(`Using streaming mode for large file (${formatBytes(fileSizeBytes)}): ${filePath}`);
        xmlContent = await streamXMLContent(filePath, fileSizeBytes, options);
    } else {
        // Use standard file reading for smaller files
        xmlContent = await readFileWithTimeout(filePath, options.timeoutMs ?? 120000);
        
        if (options.onProgress) {
            options.onProgress({
                bytesProcessed: fileSizeBytes,
                totalBytes: fileSizeBytes,
                percentage: 100,
                stage: 'File read complete'
            });
        }
    }

    // Always validate security regardless of parsing method
    try {
        validateXmlSecurity(xmlContent);
    } catch (error) {
        throw new Error(`Security validation failed for ${filePath}: ${error}`);
    }

    return xmlContent;
}

/**
 * File reading with timeout support
 */
async function readFileWithTimeout(filePath: string, timeoutMs: number): Promise<string> {
    const fs = await import('fs/promises');
    
    return new Promise((resolve, reject) => {
        let timeoutId: NodeJS.Timeout | undefined;
        
        if (timeoutMs > 0) {
            timeoutId = setTimeout(() => {
                reject(new Error(`File read timed out after ${timeoutMs}ms for file: ${filePath}`));
            }, timeoutMs);
        }

        fs.readFile(filePath, 'utf8')
            .then(content => {
                if (timeoutId) clearTimeout(timeoutId);
                resolve(content);
            })
            .catch(error => {
                if (timeoutId) clearTimeout(timeoutId);
                reject(error);
            });
    });
}

/**
 * Format bytes for human-readable display
 */
function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
