import { logger } from './logger.js';

export interface PerformanceMetrics {
    operation: string;
    duration: number;
    memoryUsage: {
        before: NodeJS.MemoryUsage;
        after: NodeJS.MemoryUsage;
        delta: {
            heapUsed: number;
            external: number;
            rss: number;
        };
    };
    success: boolean;
    error?: string;
}

export class PerformanceMonitor {
    private metrics: PerformanceMetrics[] = [];

    /**
     * Measure and track operation performance
     */
    async measure<T>(
        operation: string,
        fn: () => Promise<T>,
        metadata?: Record<string, any>
    ): Promise<T> {
        const startTime = Date.now();
        const memoryBefore = process.memoryUsage();
        
        return logger.measureOperation(operation, async () => {
            try {
                const result = await fn();
                const endTime = Date.now();
                const memoryAfter = process.memoryUsage();
                
                this.recordMetrics({
                    operation,
                    duration: endTime - startTime,
                    memoryUsage: {
                        before: memoryBefore,
                        after: memoryAfter,
                        delta: {
                            heapUsed: memoryAfter.heapUsed - memoryBefore.heapUsed,
                            external: memoryAfter.external - memoryBefore.external,
                            rss: memoryAfter.rss - memoryBefore.rss
                        }
                    },
                    success: true
                });
                
                return result;
            } catch (error) {
                const endTime = Date.now();
                const memoryAfter = process.memoryUsage();
                
                this.recordMetrics({
                    operation,
                    duration: endTime - startTime,
                    memoryUsage: {
                        before: memoryBefore,
                        after: memoryAfter,
                        delta: {
                            heapUsed: memoryAfter.heapUsed - memoryBefore.heapUsed,
                            external: memoryAfter.external - memoryBefore.external,
                            rss: memoryAfter.rss - memoryBefore.rss
                        }
                    },
                    success: false,
                    error: (error as Error).message
                });
                
                throw error;
            }
        }, metadata);
    }

    private recordMetrics(metrics: PerformanceMetrics): void {
        this.metrics.push(metrics);
        
        // Log performance insights
        const memoryDeltaMB = Math.round(metrics.memoryUsage.delta.heapUsed / 1024 / 1024);
        
        logger.info(
            `Performance: ${metrics.operation} completed in ${metrics.duration}ms, memory delta: ${memoryDeltaMB}MB`,
            { correlationId: '', operation: 'performance-tracking', startTime: Date.now() },
            {
                duration: metrics.duration,
                memoryDelta: memoryDeltaMB,
                success: metrics.success,
                ...(metrics.error && { error: metrics.error })
            }
        );
    }

    /**
     * Get performance summary for all operations
     */
    getSummary(): {
        totalOperations: number;
        successRate: number;
        averageDuration: number;
        totalMemoryDelta: number;
        slowestOperation: PerformanceMetrics | null;
        heaviestMemoryOperation: PerformanceMetrics | null;
        } {
        if (this.metrics.length === 0) {
            return {
                totalOperations: 0,
                successRate: 0,
                averageDuration: 0,
                totalMemoryDelta: 0,
                slowestOperation: null,
                heaviestMemoryOperation: null
            };
        }

        const successful = this.metrics.filter(m => m.success);
        const totalDuration = this.metrics.reduce((sum, m) => sum + m.duration, 0);
        const totalMemoryDelta = this.metrics.reduce((sum, m) => sum + m.memoryUsage.delta.heapUsed, 0);
        
        const slowestOperation = this.metrics.reduce((slowest, current) => 
            current.duration > (slowest?.duration || 0) ? current : slowest
        );
        
        const heaviestMemoryOperation = this.metrics.reduce((heaviest, current) => 
            current.memoryUsage.delta.heapUsed > (heaviest?.memoryUsage.delta.heapUsed || 0) ? current : heaviest
        );

        return {
            totalOperations: this.metrics.length,
            successRate: successful.length / this.metrics.length,
            averageDuration: totalDuration / this.metrics.length,
            totalMemoryDelta: Math.round(totalMemoryDelta / 1024 / 1024), // MB
            slowestOperation,
            heaviestMemoryOperation
        };
    }

    /**
     * Log performance summary
     */
    logSummary(): void {
        const summary = this.getSummary();
        
        logger.info(
            'Performance Summary',
            { correlationId: '', operation: 'performance-summary', startTime: Date.now() },
            {
                totalOperations: summary.totalOperations,
                successRate: `${(summary.successRate * 100).toFixed(1)}%`,
                averageDuration: `${summary.averageDuration.toFixed(0)}ms`,
                totalMemoryDelta: `${summary.totalMemoryDelta}MB`,
                slowestOperation: summary.slowestOperation?.operation,
                heaviestMemoryOperation: summary.heaviestMemoryOperation?.operation
            }
        );
    }

    /**
     * Clear all collected metrics
     */
    reset(): void {
        this.metrics = [];
    }
}

// Export singleton instance
export const performanceMonitor = new PerformanceMonitor();
