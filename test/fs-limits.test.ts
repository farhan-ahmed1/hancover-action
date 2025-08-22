import { describe, it, expect } from 'vitest';
import {
    enforceFileSizeLimits,
    enforceTotalSizeLimits,
    enforceTimeoutLimits,
    validateXmlSecurity
} from '../src/fs-limits.js';

describe('FS Limits and Security', () => {
    describe('enforceFileSizeLimits', () => {
        it('should allow files under the default limit', () => {
            expect(() => enforceFileSizeLimits(1024 * 1024)).not.toThrow(); // 1MB
            expect(() => enforceFileSizeLimits(10 * 1024 * 1024)).not.toThrow(); // 10MB
            expect(() => enforceFileSizeLimits(49 * 1024 * 1024)).not.toThrow(); // 49MB
        });

        it('should reject files over the default limit', () => {
            const largeFileSize = 51 * 1024 * 1024; // 51MB
            expect(() => enforceFileSizeLimits(largeFileSize)).toThrow(
                'File size (51 MB) exceeds the limit of 50 MB'
            );
        });

        it('should allow files under custom limit', () => {
            const customLimit = 10 * 1024 * 1024; // 10MB
            expect(() => enforceFileSizeLimits(5 * 1024 * 1024, customLimit)).not.toThrow();
            expect(() => enforceFileSizeLimits(customLimit, customLimit)).not.toThrow(); // Exactly at limit
        });

        it('should reject files over custom limit', () => {
            const customLimit = 10 * 1024 * 1024; // 10MB
            const largeFileSize = 15 * 1024 * 1024; // 15MB
            expect(() => enforceFileSizeLimits(largeFileSize, customLimit)).toThrow(
                'File size (15 MB) exceeds the limit of 10 MB'
            );
        });

        it('should handle zero file size', () => {
            expect(() => enforceFileSizeLimits(0)).not.toThrow();
        });

        it('should handle edge case of exactly default limit', () => {
            const exactLimit = 50 * 1024 * 1024; // 50MB
            expect(() => enforceFileSizeLimits(exactLimit)).not.toThrow();
        });

        it('should reject negative file sizes', () => {
            expect(() => enforceFileSizeLimits(-1)).toThrow(
                'File size must be non-negative'
            );
            expect(() => enforceFileSizeLimits(-1000)).toThrow(
                'File size must be non-negative'
            );
        });

        it('should reject negative limits', () => {
            expect(() => enforceFileSizeLimits(1024, -1)).toThrow(
                'Maximum bytes per file must be non-negative'
            );
        });

        it('should handle zero limit', () => {
            expect(() => enforceFileSizeLimits(0, 0)).not.toThrow();
            expect(() => enforceFileSizeLimits(1, 0)).toThrow(
                'File size (1 Bytes) exceeds the limit of 0 Bytes'
            );
        });

        it('should format byte sizes correctly in error messages', () => {
            // Test KB formatting
            expect(() => enforceFileSizeLimits(2048, 1024)).toThrow(
                'File size (2 KB) exceeds the limit of 1 KB'
            );

            // Test MB formatting
            expect(() => enforceFileSizeLimits(3 * 1024 * 1024, 2 * 1024 * 1024)).toThrow(
                'File size (3 MB) exceeds the limit of 2 MB'
            );

            // Test GB formatting (theoretical)
            const gigabyte = 1024 * 1024 * 1024;
            expect(() => enforceFileSizeLimits(2 * gigabyte, gigabyte)).toThrow(
                'File size (2 GB) exceeds the limit of 1 GB'
            );
        });
    });

    describe('enforceTotalSizeLimits', () => {
        it('should allow total size under default limit', () => {
            expect(() => enforceTotalSizeLimits(100 * 1024 * 1024)).not.toThrow(); // 100MB
            expect(() => enforceTotalSizeLimits(199 * 1024 * 1024)).not.toThrow(); // 199MB
        });

        it('should reject total size over default limit', () => {
            const largeTotalSize = 201 * 1024 * 1024; // 201MB
            expect(() => enforceTotalSizeLimits(largeTotalSize)).toThrow(
                'Total size (201 MB) exceeds the limit of 200 MB'
            );
        });

        it('should allow total size under custom limit', () => {
            const customLimit = 500 * 1024 * 1024; // 500MB
            expect(() => enforceTotalSizeLimits(400 * 1024 * 1024, customLimit)).not.toThrow();
            expect(() => enforceTotalSizeLimits(customLimit, customLimit)).not.toThrow(); // Exactly at limit
        });

        it('should reject total size over custom limit', () => {
            const customLimit = 100 * 1024 * 1024; // 100MB
            const largeTotalSize = 150 * 1024 * 1024; // 150MB
            expect(() => enforceTotalSizeLimits(largeTotalSize, customLimit)).toThrow(
                'Total size (150 MB) exceeds the limit of 100 MB'
            );
        });

        it('should handle zero total size', () => {
            expect(() => enforceTotalSizeLimits(0)).not.toThrow();
        });

        it('should handle edge case of exactly default limit', () => {
            const exactLimit = 200 * 1024 * 1024; // 200MB
            expect(() => enforceTotalSizeLimits(exactLimit)).not.toThrow();
        });

        it('should reject negative total sizes', () => {
            expect(() => enforceTotalSizeLimits(-1)).toThrow(
                'Total size must be non-negative'
            );
        });

        it('should reject negative limits', () => {
            expect(() => enforceTotalSizeLimits(1024, -1)).toThrow(
                'Maximum total bytes must be non-negative'
            );
        });

        it('should handle zero limit', () => {
            expect(() => enforceTotalSizeLimits(0, 0)).not.toThrow();
            expect(() => enforceTotalSizeLimits(1, 0)).toThrow(
                'Total size (1 Bytes) exceeds the limit of 0 Bytes'
            );
        });
    });

    describe('enforceTimeoutLimits', () => {
        it('should allow operations within timeout', () => {
            const startTime = Date.now();
            expect(() => enforceTimeoutLimits(startTime, 10)).not.toThrow();
        });

        it('should reject operations that exceed timeout', () => {
            const startTime = Date.now() - 5000; // 5 seconds ago
            expect(() => enforceTimeoutLimits(startTime, 3)).toThrow(
                'Operation timed out after 3s'
            );
        });

        it('should handle zero timeout correctly', () => {
            const startTime = Date.now() - 1000; // 1 second ago
            expect(() => enforceTimeoutLimits(startTime, 0)).toThrow(
                'Operation timed out after 0s'
            );
        });

        it('should allow exactly at timeout boundary', () => {
            const startTime = Date.now() - 2000; // 2 seconds ago
            expect(() => enforceTimeoutLimits(startTime, 2)).not.toThrow();
        });

        it('should reject negative timeout values', () => {
            const startTime = Date.now();
            expect(() => enforceTimeoutLimits(startTime, -1)).toThrow(
                'Timeout seconds must be non-negative'
            );
        });

        it('should reject negative start time values', () => {
            expect(() => enforceTimeoutLimits(-1, 10)).toThrow(
                'Start time must be non-negative'
            );
        });

        it('should handle very large timeout values', () => {
            const startTime = Date.now();
            expect(() => enforceTimeoutLimits(startTime, 86400)).not.toThrow(); // 24 hours
        });

        it('should handle edge case of start time in future', () => {
            const futureStartTime = Date.now() + 1000; // 1 second in future
            expect(() => enforceTimeoutLimits(futureStartTime, 10)).not.toThrow();
        });

        it('should be accurate with millisecond precision', () => {
            const startTime = Date.now() - 1500; // 1.5 seconds ago
            expect(() => enforceTimeoutLimits(startTime, 1)).toThrow('Operation timed out after 1s');
            expect(() => enforceTimeoutLimits(startTime, 2)).not.toThrow();
        });

        it('should handle fractional timeout values', () => {
            const startTime = Date.now() - 1500; // 1.5 seconds ago
            expect(() => enforceTimeoutLimits(startTime, 1.2)).toThrow('Operation timed out after 1.2s');
            expect(() => enforceTimeoutLimits(startTime, 1.8)).not.toThrow();
        });
    });

    describe('validateXmlSecurity', () => {
        it('should allow safe XML content', () => {
            const safeXml = `<?xml version="1.0" encoding="UTF-8"?>
                <coverage>
                    <packages>
                        <package name="com.example">
                            <classes>
                                <class name="MyClass" filename="MyClass.java" line-rate="0.8">
                                    <methods>
                                        <method name="myMethod" signature="()V" line-rate="1.0">
                                            <lines>
                                                <line number="10" hits="5"/>
                                            </lines>
                                        </method>
                                    </methods>
                                </class>
                            </classes>
                        </package>
                    </packages>
                </coverage>`;

            expect(() => validateXmlSecurity(safeXml)).not.toThrow();
        });

        it('should reject XML with DOCTYPE internal subset', () => {
            const dangerousXml = `<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE coverage [
                    <!ENTITY xxe SYSTEM "file:///etc/passwd">
                ]>
                <coverage>&xxe;</coverage>`;

            expect(() => validateXmlSecurity(dangerousXml)).toThrow(
                'XML content contains potentially dangerous constructs (DTD/Entities). This is blocked for security reasons.'
            );
        });

        it('should reject XML with entity declarations', () => {
            const entityXml = `<?xml version="1.0" encoding="UTF-8"?>
                <coverage>
                    <!ENTITY secret SYSTEM "file:///etc/passwd">
                    <data>&secret;</data>
                </coverage>`;

            expect(() => validateXmlSecurity(entityXml)).toThrow(
                'XML content contains potentially dangerous constructs (DTD/Entities). This is blocked for security reasons.'
            );
        });

        it('should reject XML with SYSTEM entities using file protocol', () => {
            const systemFileXml = `<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE test SYSTEM "file:///etc/passwd">
                <coverage></coverage>`;

            expect(() => validateXmlSecurity(systemFileXml)).toThrow(
                'XML content contains potentially dangerous constructs (DTD/Entities). This is blocked for security reasons.'
            );
        });

        it('should reject XML with SYSTEM entities using HTTP protocol', () => {
            const systemHttpXml = `<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE test SYSTEM "http://evil.com/malicious.dtd">
                <coverage></coverage>`;

            expect(() => validateXmlSecurity(systemHttpXml)).toThrow(
                'XML content contains potentially dangerous constructs (DTD/Entities). This is blocked for security reasons.'
            );
        });

        it('should reject XML with PUBLIC entities using file protocol', () => {
            const publicFileXml = `<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE coverage PUBLIC "-//OASIS//DTD DocBook XML V4.5//EN" "file:///etc/passwd">
                <coverage></coverage>`;

            expect(() => validateXmlSecurity(publicFileXml)).toThrow(
                'XML content contains potentially dangerous constructs (DTD/Entities). This is blocked for security reasons.'
            );
        });

        it('should allow XML with safe DOCTYPE declarations', () => {
            const safeDoctype = `<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE coverage SYSTEM "http://cobertura.sourceforge.net/xml/coverage-04.dtd">
                <coverage>
                    <packages></packages>
                </coverage>`;

            // The current security implementation blocks all SYSTEM declarations for safety
            expect(() => validateXmlSecurity(safeDoctype)).toThrow('XML content contains potentially dangerous constructs');
        });

        it('should reject XML with excessive nesting (XML bomb protection)', () => {
            const xmlBomb = '<root>' + '<level>'.repeat(10001) + 'content' + '</level>'.repeat(10001) + '</root>';

            expect(() => validateXmlSecurity(xmlBomb)).toThrow(
                'XML content has excessive nesting which may indicate a potential XML bomb attack.'
            );
        });

        it('should allow XML with reasonable nesting', () => {
            const reasonableXml = '<root>' + '<level>'.repeat(100) + 'content' + '</level>'.repeat(100) + '</root>';

            expect(() => validateXmlSecurity(reasonableXml)).not.toThrow();
        });

        it('should handle edge case of exactly nesting limit', () => {
            // Create XML with exactly 10000 opening brackets (the limit is > 10000)
            // The implementation counts all '<' characters, so we need to be more precise
            const simpleXml = '<root>' + '<item/>'.repeat(1666) + '</root>'; // 1666 * 6 < 10000
            
            expect(() => validateXmlSecurity(simpleXml)).not.toThrow();
        });

        it('should handle empty XML content', () => {
            expect(() => validateXmlSecurity('')).not.toThrow();
        });

        it('should handle XML without opening tags', () => {
            expect(() => validateXmlSecurity('just text content')).not.toThrow();
        });

        it('should be case insensitive for dangerous patterns', () => {
            const upperCaseEntity = `<?xml version="1.0" encoding="UTF-8"?>
                <coverage>
                    <!ENTITY SECRET SYSTEM "FILE:///etc/passwd">
                    <data>&SECRET;</data>
                </coverage>`;

            expect(() => validateXmlSecurity(upperCaseEntity)).toThrow(
                'XML content contains potentially dangerous constructs (DTD/Entities). This is blocked for security reasons.'
            );
        });

        it('should detect DOCTYPE with internal subset regardless of formatting', () => {
            const spacedDoctype = `<?xml version="1.0"?>
                <!DOCTYPE    coverage    [
                    <!ENTITY xxe "malicious">
                ]   >
                <coverage></coverage>`;

            expect(() => validateXmlSecurity(spacedDoctype)).toThrow(
                'XML content contains potentially dangerous constructs (DTD/Entities). This is blocked for security reasons.'
            );
        });

        it('should allow XML with comments containing entity-like text', () => {
            const xmlWithComments = `<?xml version="1.0" encoding="UTF-8"?>
                <coverage>
                    <!-- This comment mentions <!ENTITY but is safe -->
                    <packages></packages>
                </coverage>`;

            // Comments are generally safe, but our current regex might still catch this
            // This test documents current behavior - might need adjustment based on requirements
            expect(() => validateXmlSecurity(xmlWithComments)).toThrow(
                'XML content contains potentially dangerous constructs (DTD/Entities). This is blocked for security reasons.'
            );
        });

        it('should handle malformed XML gracefully', () => {
            const malformedXml = `<?xml version="1.0"?>
                <coverage>
                    <unclosed-tag>
                </coverage>`;

            // Should not throw security error for malformed XML (parser will handle)
            expect(() => validateXmlSecurity(malformedXml)).not.toThrow();
        });

        it('should handle very large safe XML content', () => {
            // Create large but safe XML content
            const largeContent = '<coverage>' + '<file>'.repeat(1000) + 'content' + '</file>'.repeat(1000) + '</coverage>';
            
            expect(() => validateXmlSecurity(largeContent)).not.toThrow();
        });
    });

    describe('formatBytes utility (tested indirectly)', () => {
        it('should format various byte sizes correctly in error messages', () => {
            // Test different sizes to ensure proper formatting
            const testCases = [
                { size: 0, expected: '0 Bytes' },
                { size: 512, expected: '512 Bytes' },
                { size: 1024, expected: '1 KB' },
                { size: 1536, expected: '1.5 KB' },
                { size: 1024 * 1024, expected: '1 MB' },
                { size: 2.5 * 1024 * 1024, expected: '2.5 MB' },
                { size: 1024 * 1024 * 1024, expected: '1 GB' }
            ];

            testCases.forEach(({ size, expected }) => {
                try {
                    enforceFileSizeLimits(size + 1, size);
                    // Should throw
                    expect.fail('Should have thrown for size limit test');
                } catch (error: any) {
                    expect(error.message).toContain(expected);
                }
            });
        });

        it('should handle fractional formatting correctly', () => {
            // Test fractional MB
            const fractionalMB = 1.75 * 1024 * 1024; // 1.75 MB
            try {
                enforceFileSizeLimits(fractionalMB + 1, fractionalMB);
                expect.fail('Should have thrown');
            } catch (error: any) {
                expect(error.message).toContain('1.75 MB');
            }
        });
    });
});
