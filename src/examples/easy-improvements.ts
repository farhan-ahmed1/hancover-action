/**
 * Example: Simple Integration of Easy Improvements
 * 
 * This file demonstrates how to quickly integrate the easiest improvements
 * identified in the analysis with minimal effort but high impact.
 */

import { logger } from '../infrastructure/logger.js';
import { performanceMonitor } from '../infrastructure/performance-monitor.js';
import { validateInputs } from '../infrastructure/input-validator.js';

/**
 * Example of how to use the new utilities for any operation
 */
export async function exampleOperation(files: string[], timeoutSeconds: number = 120) {
    // 1. ✅ STRUCTURED LOGGING - Track operations with correlation IDs
    const context = logger.createContext('example-operation', { 
        fileCount: files.length,
        timeout: timeoutSeconds
    });
    
    try {
        // 2. ✅ INPUT VALIDATION - Comprehensive validation with helpful messages
        logger.info('Validating inputs...', context);
        const validation = validateInputs({
            files,
            timeoutSeconds,
            maxBytesPerFile: 50 * 1024 * 1024,
            maxTotalBytes: 200 * 1024 * 1024
        });

        if (!validation.success) {
            const errorMsg = `Validation failed: ${validation.errors.map(e => e.message).join(', ')}`;
            logger.error(errorMsg, context);
            throw new Error(errorMsg);
        }

        if (validation.warnings.length > 0) {
            logger.warning(`Validation warnings: ${validation.warnings.map(w => w.message).join(', ')}`, context);
        }

        // 3. ✅ PERFORMANCE MONITORING - Measure critical operations
        const result = await performanceMonitor.measure(
            'process-files',
            async () => {
                logger.info(`Processing ${files.length} files...`, context);
                
                // Simulate file processing
                const results = [];
                for (const file of files) {
                    await new Promise(resolve => setTimeout(resolve, 100)); // Simulate work
                    results.push({ file, processed: true });
                }
                
                return results;
            },
            { operation: 'file-processing', inputSize: files.length }
        );

        logger.info('Operation completed successfully', context, { 
            filesProcessed: result.length 
        });

        // 4. ✅ PERFORMANCE SUMMARY - Show metrics at the end
        performanceMonitor.logSummary();
        
        return result;

    } catch (error) {
        logger.error('Operation failed', context, error as Error);
        throw error;
    }
}

/**
 * Example of wrapping existing functions with performance monitoring
 */
export function wrapWithMonitoring<T extends any[], R>(
    operationName: string,
    // eslint-disable-next-line no-unused-vars
    originalFunction: (...args: T) => Promise<R>
) {
    return async (...args: T): Promise<R> => {
        return performanceMonitor.measure(
            operationName,
            () => originalFunction(...args),
            { argumentCount: args.length }
        );
    };
}

/**
 * Example of creating a logger for a specific module
 */
export function createModuleLogger(moduleName: string) {
    return {
        info: (message: string, metadata?: Record<string, any>) => {
            const context = logger.createContext(moduleName, metadata);
            logger.info(message, context);
        },
        
        error: (message: string, error?: Error, metadata?: Record<string, any>) => {
            const context = logger.createContext(moduleName, metadata);
            logger.error(message, context, error);
        },
        
        warning: (message: string, metadata?: Record<string, any>) => {
            const context = logger.createContext(moduleName, metadata);
            logger.warning(message, context);
        },
        
        measure: async <T>(operation: string, fn: () => Promise<T>) => {
            return performanceMonitor.measure(`${moduleName}:${operation}`, fn);
        }
    };
}

// Usage examples:

/**
 * How to use in existing code with minimal changes:
 * 
 * // Before:
 * console.log('Starting processing...');
 * const result = await processFiles(files);
 * console.log('Done');
 * 
 * // After (1-line change):
 * const result = await performanceMonitor.measure('process-files', 
 *     () => processFiles(files)
 * );
 * 
 * // Or for more detailed logging:
 * const moduleLogger = createModuleLogger('file-processor');
 * moduleLogger.info('Starting processing...', { fileCount: files.length });
 * const result = await moduleLogger.measure('process-files', 
 *     () => processFiles(files)
 * );
 */

/**
 * Quick wins checklist for existing code:
 * 
 * ✅ 1. Add structured logging (5 minutes):
 *    - Import { logger } from '../infrastructure/logger.js'
 *    - Replace console.log with logger.info
 *    - Add context with logger.createContext()
 * 
 * ✅ 2. Add performance monitoring (2 minutes):
 *    - Import { performanceMonitor } from '../infrastructure/performance-monitor.js'
 *    - Wrap critical operations with performanceMonitor.measure()
 *    - Add performanceMonitor.logSummary() at the end
 * 
 * ✅ 3. Add input validation (10 minutes):
 *    - Import { validateInputs } from '../infrastructure/input-validator.js'
 *    - Call validateInputs() early in the function
 *    - Handle validation results appropriately
 * 
 * ✅ 4. Better error messages (3 minutes):
 *    - Use logger.error() instead of console.error
 *    - Include context and metadata in error logs
 *    - Add helpful suggestions in error messages
 */
