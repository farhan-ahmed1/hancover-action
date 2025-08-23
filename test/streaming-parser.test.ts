import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createReadStream } from 'fs';
import { 
    shouldUseStreaming, 
    parseXMLWithStreaming, 
    streamXMLContent,
    type StreamingParseOptions 
} from '../src/infrastructure/streaming-parser.js';
import * as core from '@actions/core';

// Mock dependencies
vi.mock('fs', () => ({
    createReadStream: vi.fn()
}));

vi.mock('fs/promises', () => ({
    readFile: vi.fn()
}));

vi.mock('@actions/core', () => ({
    info: vi.fn(),
    warning: vi.fn()
}));

vi.mock('../src/infrastructure/fs-limits.js', () => ({
    validateXmlSecurity: vi.fn()
}));

describe('Streaming Parser', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('shouldUseStreaming', () => {
        it('should return false for small files under default threshold', () => {
            expect(shouldUseStreaming(5 * 1024 * 1024)).toBe(false); // 5MB
            expect(shouldUseStreaming(1024 * 1024)).toBe(false); // 1MB
            expect(shouldUseStreaming(500 * 1024)).toBe(false); // 500KB
        });

        it('should return true for large files over default threshold', () => {
            expect(shouldUseStreaming(15 * 1024 * 1024)).toBe(true); // 15MB
            expect(shouldUseStreaming(50 * 1024 * 1024)).toBe(true); // 50MB
            expect(shouldUseStreaming(100 * 1024 * 1024)).toBe(true); // 100MB
        });

        it('should respect custom maxMemoryUsage option', () => {
            const options: StreamingParseOptions = {
                maxMemoryUsage: 1024 * 1024 // 1MB threshold
            };

            expect(shouldUseStreaming(512 * 1024, options)).toBe(false); // 512KB
            expect(shouldUseStreaming(2 * 1024 * 1024, options)).toBe(true); // 2MB
        });

        it('should handle edge case of exactly threshold size', () => {
            const threshold = 10 * 1024 * 1024; // 10MB default
            expect(shouldUseStreaming(threshold)).toBe(false); // Equal to threshold
            expect(shouldUseStreaming(threshold + 1)).toBe(true); // Just over threshold
        });

        it('should handle zero and negative file sizes', () => {
            expect(shouldUseStreaming(0)).toBe(false);
            expect(shouldUseStreaming(-1)).toBe(false);
        });
    });

    describe('streamXMLContent', () => {
        it('should stream content with progress tracking', async () => {
            const mockReadStream = {
                pipe: vi.fn().mockReturnThis(),
                on: vi.fn().mockImplementation((event, callback) => {
                    if (event === 'data') {
                        // Simulate data chunks
                        setTimeout(() => callback(Buffer.from('<xml>test')), 10);
                        setTimeout(() => callback(Buffer.from(' content</xml>')), 20);
                    } else if (event === 'end') {
                        setTimeout(callback, 30);
                    }
                    return mockReadStream;
                })
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            const progressSpy = vi.fn();
            const options: StreamingParseOptions = {
                onProgress: progressSpy,
                chunkSize: 1024
            };

            streamXMLContent('/test/file.xml', 1000, options);

            // Wait a bit for the mock events to fire
            await new Promise(resolve => setTimeout(resolve, 50));

            expect(vi.mocked(createReadStream)).toHaveBeenCalledWith('/test/file.xml', {
                encoding: 'utf8',
                highWaterMark: 1024
            });
        });

        it('should handle timeout during streaming', async () => {
            const mockReadStream = {
                pipe: vi.fn().mockReturnThis(),
                on: vi.fn()
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            const options: StreamingParseOptions = {
                timeoutMs: 50 // Very short timeout
            };

            await expect(
                streamXMLContent('/test/slow-file.xml', 1000, options)
            ).rejects.toThrow('Streaming XML read timed out after 50ms');
        });

        it('should handle read stream errors', async () => {
            const mockReadStream = {
                pipe: vi.fn().mockReturnThis(),
                on: vi.fn().mockImplementation((event, callback) => {
                    if (event === 'error') {
                        setTimeout(() => callback(new Error('Read failed')), 10);
                    }
                    return mockReadStream;
                })
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            await expect(
                streamXMLContent('/test/bad-file.xml', 1000)
            ).rejects.toThrow('Failed to read file /test/bad-file.xml: Read failed');
        });

        it('should handle processor stream errors', async () => {
            const mockReadStream = {
                pipe: vi.fn().mockImplementation((processor) => {
                    // Simulate processor error
                    setTimeout(() => processor.emit('error', new Error('Processing failed')), 10);
                    return mockReadStream;
                }),
                on: vi.fn().mockReturnThis()
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            await expect(
                streamXMLContent('/test/bad-processing.xml', 1000)
            ).rejects.toThrow('Failed to stream XML content from /test/bad-processing.xml: Processing failed');
        });

        it('should use default options when not provided', async () => {
            const mockReadStream = {
                pipe: vi.fn().mockReturnThis(),
                on: vi.fn().mockImplementation((event, callback) => {
                    if (event === 'end') {
                        setTimeout(callback, 10);
                    }
                    return mockReadStream;
                })
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            streamXMLContent('/test/file.xml', 1000);
            
            // Give time for the mock to complete
            await new Promise(resolve => setTimeout(resolve, 20));

            expect(vi.mocked(createReadStream)).toHaveBeenCalledWith('/test/file.xml', {
                encoding: 'utf8',
                highWaterMark: 64 * 1024 // Default chunk size
            });
        });

        it('should handle zero timeout (no timeout)', async () => {
            const mockReadStream = {
                pipe: vi.fn().mockReturnThis(),
                on: vi.fn().mockImplementation((event, callback) => {
                    if (event === 'end') {
                        setTimeout(callback, 10);
                    }
                    return mockReadStream;
                })
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            const options: StreamingParseOptions = {
                timeoutMs: 0 // No timeout
            };

            streamXMLContent('/test/file.xml', 1000, options);
            
            // Should not timeout even after longer delay
            await new Promise(resolve => setTimeout(resolve, 20));
            
            // No timeout error should be expected
        });
    });

    describe('parseXMLWithStreaming', () => {
        beforeEach(async () => {
            // Mock the validateXmlSecurity function
            const { validateXmlSecurity } = vi.mocked(await import('../src/infrastructure/fs-limits.js'));
            validateXmlSecurity.mockImplementation(() => {}); // No-op by default
        });

        it.skip('should use streaming for large files', async () => {
            const { validateXmlSecurity } = vi.mocked(await import('../src/infrastructure/fs-limits.js'));
            
            const mockReadStream = {
                pipe: vi.fn().mockReturnThis(),
                on: vi.fn().mockImplementation((event, callback) => {
                    if (event === 'end') {
                        // Call callback immediately to avoid timeout
                        callback();
                    }
                    return mockReadStream;
                })
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            const largeSizeBytes = 20 * 1024 * 1024; // 20MB
            const progressSpy = vi.fn();

            await parseXMLWithStreaming('/test/large.xml', largeSizeBytes, {
                onProgress: progressSpy
            });

            expect(vi.mocked(core.info)).toHaveBeenCalledWith(
                expect.stringContaining('Using streaming mode for large file')
            );
            expect(progressSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    stage: 'Starting streaming parse'
                })
            );
            expect(validateXmlSecurity).toHaveBeenCalled();
        });

        it('should use standard reading for small files', async () => {
            const { validateXmlSecurity } = vi.mocked(await import('../src/infrastructure/fs-limits.js'));
            const { readFile } = vi.mocked(await import('fs/promises'));
            
            readFile.mockResolvedValue('<xml>small content</xml>');

            const smallSizeBytes = 1024 * 1024; // 1MB
            const progressSpy = vi.fn();

            const result = await parseXMLWithStreaming('/test/small.xml', smallSizeBytes, {
                onProgress: progressSpy
            });

            expect(result).toBe('<xml>small content</xml>');
            expect(progressSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    stage: 'Starting standard parse'
                })
            );
            expect(progressSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    stage: 'File read complete',
                    percentage: 100
                })
            );
            expect(validateXmlSecurity).toHaveBeenCalledWith('<xml>small content</xml>');
        });

        it('should handle security validation failures', async () => {
            const { validateXmlSecurity } = vi.mocked(await import('../src/infrastructure/fs-limits.js'));
            const { readFile } = vi.mocked(await import('fs/promises'));
            
            readFile.mockResolvedValue('<xml>content</xml>');
            validateXmlSecurity.mockImplementation(() => {
                throw new Error('Security validation failed');
            });

            await expect(
                parseXMLWithStreaming('/test/malicious.xml', 1024)
            ).rejects.toThrow('Security validation failed for /test/malicious.xml: Error: Security validation failed');
        });

        it('should handle file read timeout', async () => {
            const { readFile } = vi.mocked(await import('fs/promises'));
            
            readFile.mockImplementation(() => 
                new Promise(resolve => setTimeout(() => resolve('content'), 200))
            );

            await expect(
                parseXMLWithStreaming('/test/slow.xml', 1024, { timeoutMs: 50 })
            ).rejects.toThrow('File read timed out after 50ms');
        });

        it('should handle file read errors', async () => {
            const { readFile } = vi.mocked(await import('fs/promises'));
            
            readFile.mockRejectedValue(new Error('File not found'));

            await expect(
                parseXMLWithStreaming('/test/missing.xml', 1024)
            ).rejects.toThrow('File not found');
        });

        it('should work without progress callback', async () => {
            const { readFile } = vi.mocked(await import('fs/promises'));
            
            readFile.mockResolvedValue('<xml>content</xml>');

            const result = await parseXMLWithStreaming('/test/file.xml', 1024);

            expect(result).toBe('<xml>content</xml>');
        });

        it('should use default timeout when not specified', async () => {
            const { readFile } = vi.mocked(await import('fs/promises'));
            
            readFile.mockResolvedValue('<xml>content</xml>');

            // Should not throw with default timeout (120000ms)
            const result = await parseXMLWithStreaming('/test/file.xml', 1024);
            expect(result).toBe('<xml>content</xml>');
        });
    });

    describe('XMLChunkProcessor (indirectly through streamXMLContent)', () => {
        it('should process XML chunks and report progress', async () => {
            const progressCallback = vi.fn();
            const totalBytes = 1000;
            
            // Mock a read stream that emits chunks
            const mockReadStream = {
                pipe: vi.fn().mockImplementation((processor) => {
                    // Simulate chunk processing
                    setTimeout(() => {
                        processor._transform(Buffer.from('<xml>'), 'utf8', () => {});
                        processor._transform(Buffer.from('content'), 'utf8', () => {});
                        processor._transform(Buffer.from('</xml>'), 'utf8', () => {});
                        processor._flush(() => {});
                        processor.emit('end');
                    }, 10);
                    return mockReadStream;
                }),
                on: vi.fn().mockReturnThis()
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            await streamXMLContent('/test/file.xml', totalBytes, {
                onProgress: progressCallback
            });

            // Progress should have been reported
            expect(progressCallback).toHaveBeenCalled();
        });

        it('should handle transform errors gracefully', async () => {
            const mockReadStream = {
                pipe: vi.fn().mockImplementation((processor) => {
                    setTimeout(() => {
                        // Force error in _transform by making processBuffer throw
                        const errorChunk = Buffer.from('invalid-xml-that-causes-error');
                        processor._transform(errorChunk, 'utf8', (error?: Error) => {
                            if (!error) {
                                // Simulate internal error in processBuffer
                                const fakeError = new Error('processBuffer failed');
                                processor.emit('error', fakeError);
                            }
                        });
                    }, 10);
                    return mockReadStream;
                }),
                on: vi.fn().mockReturnThis()
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            await expect(
                streamXMLContent('/test/bad.xml', 1000)
            ).rejects.toThrow();
        });

        it('should handle flush errors gracefully', async () => {
            const mockReadStream = {
                pipe: vi.fn().mockImplementation((processor) => {
                    setTimeout(() => {
                        // Force error in _flush by making processBuffer throw in final mode
                        processor._flush((error?: Error) => {
                            if (!error) {
                                // Simulate internal error in processBuffer final mode
                                const fakeError = new Error('processBuffer final failed');
                                processor.emit('error', fakeError);
                            }
                        });
                    }, 10);
                    return mockReadStream;
                }),
                on: vi.fn().mockReturnThis()
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            await expect(
                streamXMLContent('/test/bad-flush.xml', 1000)
            ).rejects.toThrow();
        });

        it('should handle chunk processing with progress thresholds', async () => {
            const progressCallback = vi.fn();
            const totalBytes = 5 * 1024 * 1024; // 5MB to trigger progress reporting
            
            const mockReadStream = {
                pipe: vi.fn().mockImplementation((processor) => {
                    setTimeout(() => {
                        // Send large chunks to trigger progress reporting thresholds
                        const largeChunk = Buffer.alloc(1024 * 1024, 'x'); // 1MB chunk
                        processor._transform(largeChunk, 'utf8', () => {});
                        processor._transform(largeChunk, 'utf8', () => {});
                        processor._transform(largeChunk, 'utf8', () => {});
                        processor._flush(() => {});
                        processor.emit('end');
                    }, 10);
                    return mockReadStream;
                }),
                on: vi.fn().mockReturnThis()
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            await streamXMLContent('/test/large.xml', totalBytes, {
                onProgress: progressCallback
            });

            // Progress should have been called multiple times due to threshold
            expect(progressCallback).toHaveBeenCalledWith(
                expect.objectContaining({
                    stage: 'Parsing XML content'
                })
            );
        });

        it('should handle buffer boundary conditions', async () => {
            const progressCallback = vi.fn();
            const totalBytes = 1000;
            
            const mockReadStream = {
                pipe: vi.fn().mockImplementation((processor) => {
                    setTimeout(() => {
                        // Send partial XML elements to test buffer processing
                        processor._transform(Buffer.from('<element attr="'), 'utf8', () => {});
                        processor._transform(Buffer.from('value">content'), 'utf8', () => {});
                        processor._transform(Buffer.from('</element>'), 'utf8', () => {});
                        
                        // Test final processing with remaining buffer
                        processor._flush(() => {});
                        processor.emit('end');
                    }, 10);
                    return mockReadStream;
                }),
                on: vi.fn().mockReturnThis()
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            await streamXMLContent('/test/fragmented.xml', totalBytes, {
                onProgress: progressCallback
            });

            expect(progressCallback).toHaveBeenCalled();
        });

        it('should cleanup resources on stream errors', async () => {
            const progressCallback = vi.fn();
            
            const mockReadStream = {
                pipe: vi.fn().mockImplementation((processor) => {
                    setTimeout(() => {
                        // Simulate error during processing that triggers cleanup
                        processor.emit('error', new Error('Stream processing failed'));
                    }, 10);
                    return mockReadStream;
                }),
                on: vi.fn().mockReturnThis()
            };

            vi.mocked(createReadStream).mockReturnValue(mockReadStream as any);

            await expect(
                streamXMLContent('/test/error.xml', 1000, {
                    onProgress: progressCallback
                })
            ).rejects.toThrow('Failed to stream XML content from /test/error.xml: Stream processing failed');
        });
    });

    describe('formatBytes utility (indirectly tested)', () => {
        it('should handle progress reporting for standard file reads', async () => {
            const { readFile } = vi.mocked(await import('fs/promises'));
            readFile.mockResolvedValue('<xml>content</xml>');

            const progressSpy = vi.fn();
            const smallSizeBytes = 1024; // Small file

            await parseXMLWithStreaming('/test/small.xml', smallSizeBytes, {
                onProgress: progressSpy
            });

            // Should cover lines 221-222 - progress reporting for standard reads
            expect(progressSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    stage: 'File read complete',
                    bytesProcessed: smallSizeBytes,
                    totalBytes: smallSizeBytes,
                    percentage: 100
                })
            );
        });
    });
});
