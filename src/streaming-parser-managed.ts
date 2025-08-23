/**
 * Enhanced streaming parser with resource management and automatic cleanup
 */

import { createReadStream } from 'fs';
import { Transform } from 'stream';
import * as core from '@actions/core';
import { validateXmlSecurity } from './fs-limits.js';
import { 
    Disposable, 
    withResourceTracking,
    DisposableTimeout
} from './resource-management.js';

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
 * Disposable wrapper for Node.js streams with automatic cleanup
 */
class DisposableStream implements Disposable {
    private disposed = false;
    private readonly cleanupCallbacks: (() => void)[] = [];

    constructor(
        public readonly stream: NodeJS.ReadableStream | NodeJS.WritableStream | Transform,
        public readonly streamName: string
    ) {}

    /**
     * Add a cleanup callback to be executed during disposal
     */
    addCleanupCallback(callback: () => void): void {
        if (this.disposed) {
            throw new Error('Cannot add cleanup callback to disposed stream');
        }
        this.cleanupCallbacks.push(callback);
    }

    /**
     * Get the underlying stream
     */
    get underlying(): NodeJS.ReadableStream | NodeJS.WritableStream | Transform {
        if (this.disposed) {
            throw new Error('Cannot access disposed stream');
        }
        return this.stream;
    }

    /**
     * Get the stream name for debugging
     */
    get name(): string {
        return this.streamName;
    }

    /**
     * Check if the stream has been disposed
     */
    get isDisposed(): boolean {
        return this.disposed;
    }

    /**
     * Dispose of the stream and run cleanup callbacks
     */
    dispose(): void {
        if (this.disposed) {
            return;
        }

        this.disposed = true;

        try {
            // Run cleanup callbacks first
            for (const callback of this.cleanupCallbacks) {
                try {
                    callback();
                } catch (error) {
                    core.warning(`Error in stream cleanup callback for ${this.streamName}: ${error}`);
                }
            }

            // Remove all listeners to prevent leaks
            if ('removeAllListeners' in this.stream && typeof this.stream.removeAllListeners === 'function') {
                this.stream.removeAllListeners();
            }

            // Destroy the stream if possible
            if ('destroy' in this.stream && typeof this.stream.destroy === 'function') {
                this.stream.destroy();
            }

            core.debug(`Successfully disposed stream: ${this.streamName}`);
        } catch (error) {
            core.warning(`Error disposing stream ${this.streamName}: ${error}`);
        }
    }
}

/**
 * Enhanced XML chunk processor with proper resource management
 */
class ManagedXMLChunkProcessor extends Transform implements Disposable {
    private buffer = '';
    private elementStack: string[] = [];
    private inElement = false;
    private currentElement = '';
    private onProgress?: ProgressCallback;
    private bytesProcessed = 0;
    private totalBytes: number;
    private lastProgressUpdate = 0;
    private disposed = false;

    constructor(totalBytes: number, onProgress?: ProgressCallback) {
        super({ objectMode: true });
        this.totalBytes = totalBytes;
        this.onProgress = onProgress;
    }

    _transform(chunk: any, encoding: BufferEncoding, callback: Function) {
        if (this.disposed) {
            callback(new Error('Cannot process chunks on disposed processor'));
            return;
        }

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
        if (this.disposed) {
            callback(new Error('Cannot flush disposed processor'));
            return;
        }

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
        if (!this.disposed) {
            // Emit complete XML fragments for downstream processing
            this.push(element);
        }
    }

    private reportProgress(stage: string) {
        if (this.onProgress && !this.disposed) {
            const percentage = Math.min((this.bytesProcessed / this.totalBytes) * 100, 100);
            this.onProgress({
                bytesProcessed: this.bytesProcessed,
                totalBytes: this.totalBytes,
                percentage,
                stage
            });
        }
    }

    /**
     * Dispose of the processor and clear internal state
     */
    dispose(): void {
        if (this.disposed) {
            return;
        }

        this.disposed = true;
        this.buffer = '';
        this.elementStack = [];
        this.onProgress = undefined;
        
        // Destroy the transform stream
        this.destroy();
    }
}

/**
 * Check if a file should be parsed using streaming mode based on size
 */
export function shouldUseStreaming(fileSizeBytes: number, options: StreamingParseOptions = {}): boolean {
    const maxMemoryUsage = options.maxMemoryUsage ?? 10 * 1024 * 1024; // 10MB default
    return fileSizeBytes > maxMemoryUsage;
}

/**
 * Enhanced stream-based XML content reader with comprehensive resource management
 */
export async function streamXMLContentWithManagement(
    filePath: string, 
    totalBytes: number,
    options: StreamingParseOptions = {}
): Promise<string> {
    return withResourceTracking(async (tracker) => {
        const { timeoutMs = 120000, chunkSize = 64 * 1024, onProgress } = options;

        return new Promise<string>((resolve, reject) => {
            let content = '';
            let completed = false;

            // Set up timeout with proper resource tracking
            let timeoutDisposable: DisposableTimeout | undefined;
            if (timeoutMs > 0) {
                timeoutDisposable = new DisposableTimeout(
                    () => {
                        if (!completed) {
                            completed = true;
                            reject(new Error(`Streaming XML read timed out after ${timeoutMs}ms for file: ${filePath}`));
                        }
                    },
                    timeoutMs
                );
                tracker.track(timeoutDisposable);
                timeoutDisposable.start();
            }

            const cleanup = () => {
                completed = true;
            };

            try {
                const readStream = createReadStream(filePath, { 
                    encoding: 'utf8',
                    highWaterMark: chunkSize 
                });

                const disposableReadStream = new DisposableStream(readStream, `ReadStream:${filePath}`);
                tracker.track(disposableReadStream);

                const processor = new ManagedXMLChunkProcessor(totalBytes, onProgress);
                tracker.track(processor);

                // Collect processed chunks
                processor.on('data', (chunk) => {
                    if (!completed) {
                        content += chunk;
                    }
                });

                processor.on('end', () => {
                    if (!completed) {
                        cleanup();
                        resolve(content);
                    }
                });

                processor.on('error', (error) => {
                    if (!completed) {
                        cleanup();
                        reject(new Error(`Failed to stream XML content from ${filePath}: ${error.message}`));
                    }
                });

                readStream.on('error', (error) => {
                    if (!completed) {
                        cleanup();
                        reject(new Error(`Failed to read file ${filePath}: ${error.message}`));
                    }
                });

                // Connect streams
                readStream.pipe(processor);

            } catch (error) {
                if (!completed) {
                    cleanup();
                    reject(error);
                }
            }
        });
    });
}

/**
 * Enhanced XML parsing with streaming support and comprehensive resource management
 */
export async function parseXMLWithManagedStreaming(
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
        xmlContent = await streamXMLContentWithManagement(filePath, fileSizeBytes, options);
    } else {
        // Use standard file reading for smaller files with resource management
        xmlContent = await readFileWithManagedTimeout(filePath, options.timeoutMs ?? 120000);
        
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
 * File reading with timeout support and resource management
 */
async function readFileWithManagedTimeout(filePath: string, timeoutMs: number): Promise<string> {
    return withResourceTracking(async (tracker) => {
        const fs = await import('fs/promises');
        
        return new Promise<string>((resolve, reject) => {
            let completed = false;
            
            // Set up timeout with resource tracking
            let timeoutDisposable: DisposableTimeout | undefined;
            if (timeoutMs > 0) {
                timeoutDisposable = new DisposableTimeout(
                    () => {
                        if (!completed) {
                            completed = true;
                            reject(new Error(`File read timed out after ${timeoutMs}ms for file: ${filePath}`));
                        }
                    },
                    timeoutMs
                );
                tracker.track(timeoutDisposable);
                timeoutDisposable.start();
            }

            fs.readFile(filePath, 'utf8')
                .then(content => {
                    if (!completed) {
                        completed = true;
                        resolve(content);
                    }
                })
                .catch(error => {
                    if (!completed) {
                        completed = true;
                        reject(error);
                    }
                });
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

// Re-export original functions for backwards compatibility with enhanced versions as defaults
export {
    streamXMLContentWithManagement as streamXMLContent,
    parseXMLWithManagedStreaming as parseXMLWithStreaming
};
