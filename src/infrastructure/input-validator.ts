import YAML from 'yaml';
import { readFileSync, existsSync } from 'fs';

export interface ValidationResult<T> {
    success: boolean;
    data?: T;
    errors: ValidationError[];
    warnings: ValidationWarning[];
}

export interface ValidationError {
    field: string;
    message: string;
    code: string;
    suggestion?: string;
}

export interface ValidationWarning {
    field: string;
    message: string;
    suggestion?: string;
}

export class EnhancedValidator {
    private errors: ValidationError[] = [];
    private warnings: ValidationWarning[] = [];

    /**
     * Validate file paths and their accessibility
     */
    validateFiles(files: string[]): this {
        if (files.length === 0) {
            this.addError('files', 'No coverage files provided', 'EMPTY_FILES_LIST', 
                'Provide at least one coverage file path in the "files" input');
            return this;
        }

        const largeFiles: string[] = [];
        const maxFileSize = 50 * 1024 * 1024; // 50MB

        for (const file of files) {
            if (!file.trim()) {
                this.addWarning('files', 'Empty file path found in files list', 
                    'Remove empty lines from the files input');
                continue;
            }

            // Check if file exists (for local testing)
            try {
                if (existsSync(file)) {
                    const stats = readFileSync(file);
                    if (stats.length > maxFileSize) {
                        largeFiles.push(file);
                    }
                }
            } catch {
                // File might not exist in CI context, that's okay
            }

            // Check for common file extension patterns
            const validExtensions = ['.xml', '.json', '.lcov', '.info', '.txt'];
            const hasValidExtension = validExtensions.some(ext => file.toLowerCase().endsWith(ext));
            
            if (!hasValidExtension) {
                this.addWarning('files', `File "${file}" doesn't have a recognized coverage format extension`, 
                    `Expected extensions: ${validExtensions.join(', ')}`);
            }
        }

        if (largeFiles.length > 0) {
            this.addWarning('files', `Large files detected: ${largeFiles.join(', ')}`, 
                'Consider using file size limits or streaming for better performance');
        }

        return this;
    }

    /**
     * Validate threshold values
     */
    validateThresholds(thresholds?: string): this {
        if (!thresholds) return this;

        try {
            const parsed = JSON.parse(thresholds);
            
            if (typeof parsed !== 'object' || parsed === null) {
                this.addError('thresholds', 'Thresholds must be a valid JSON object', 'INVALID_THRESHOLDS_FORMAT',
                    'Example: {"line": 80, "branch": 70, "function": 90}');
                return this;
            }

            const validKeys = ['line', 'branch', 'function', 'statement'];
            const invalidKeys = Object.keys(parsed).filter(key => !validKeys.includes(key));
            
            if (invalidKeys.length > 0) {
                this.addWarning('thresholds', `Unknown threshold keys: ${invalidKeys.join(', ')}`, 
                    `Valid keys are: ${validKeys.join(', ')}`);
            }

            for (const [key, value] of Object.entries(parsed)) {
                if (typeof value !== 'number') {
                    this.addError('thresholds', `Threshold "${key}" must be a number, got ${typeof value}`, 'INVALID_THRESHOLD_TYPE');
                } else if (value < 0 || value > 100) {
                    this.addError('thresholds', `Threshold "${key}" must be between 0 and 100, got ${value}`, 'INVALID_THRESHOLD_RANGE');
                }
            }
        } catch (error) {
            this.addError('thresholds', `Invalid JSON format: ${(error as Error).message}`, 'INVALID_JSON',
                'Ensure thresholds is valid JSON like {"line": 80, "branch": 70}');
        }

        return this;
    }

    /**
     * Validate groups configuration
     */
    validateGroups(groups?: string): this {
        if (!groups) return this;

        try {
            const parsed = YAML.parse(groups);
            
            if (!Array.isArray(parsed)) {
                this.addError('groups', 'Groups must be a YAML array', 'INVALID_GROUPS_FORMAT',
                    'Example: "- name: Core\\n  paths: [src/core/**]"');
                return this;
            }

            for (let i = 0; i < parsed.length; i++) {
                const group = parsed[i];
                
                if (!group.name) {
                    this.addError('groups', `Group at index ${i} is missing required "name" field`, 'MISSING_GROUP_NAME');
                }
                
                if (!group.paths || !Array.isArray(group.paths)) {
                    this.addError('groups', `Group "${group.name || i}" is missing required "paths" array`, 'MISSING_GROUP_PATHS');
                } else if (group.paths.length === 0) {
                    this.addWarning('groups', `Group "${group.name}" has empty paths array`, 
                        'Add at least one path pattern to make the group useful');
                }
            }
        } catch (error) {
            this.addError('groups', `Invalid YAML format: ${(error as Error).message}`, 'INVALID_YAML',
                'Ensure groups is valid YAML array format');
        }

        return this;
    }

    /**
     * Validate timeout and size limits
     */
    validateLimits(timeoutSeconds: number, maxBytesPerFile: number, maxTotalBytes: number): this {
        if (timeoutSeconds <= 0) {
            this.addError('timeoutSeconds', 'Timeout must be greater than 0', 'INVALID_TIMEOUT');
        } else if (timeoutSeconds > 1800) { // 30 minutes
            this.addWarning('timeoutSeconds', `Timeout of ${timeoutSeconds}s is very high`, 
                'Consider using a lower timeout (e.g., 120-300s) to avoid hanging actions');
        }

        if (maxBytesPerFile <= 0) {
            this.addError('maxBytesPerFile', 'Max bytes per file must be greater than 0', 'INVALID_FILE_SIZE_LIMIT');
        } else if (maxBytesPerFile > 100 * 1024 * 1024) { // 100MB
            this.addWarning('maxBytesPerFile', 'Very high file size limit may cause memory issues',
                'Consider using a lower limit (e.g., 10-50MB) for better performance');
        }

        if (maxTotalBytes <= maxBytesPerFile) {
            this.addError('maxTotalBytes', 'Max total bytes must be greater than max bytes per file', 'INVALID_TOTAL_SIZE_LIMIT');
        }

        return this;
    }

    /**
     * Validate GitHub integration settings
     */
    validateGitHubSettings(gistId?: string, gistToken?: string): this {
        if (gistId && !gistToken) {
            this.addWarning('gistToken', 'Gist ID provided but no token found', 
                'Set GIST_TOKEN environment variable or gist-token input to enable Gist functionality');
        }

        if (gistToken && !gistId) {
            this.addWarning('gistId', 'Gist token provided but no Gist ID', 
                'Provide gist-id input to enable Gist functionality');
        }

        // Validate gist ID format (GitHub gist IDs are 32-character hex strings)
        if (gistId && !/^[a-f0-9]{32}$/i.test(gistId)) {
            this.addError('gistId', 'Invalid Gist ID format', 'INVALID_GIST_ID',
                'Gist ID should be a 32-character hexadecimal string');
        }

        return this;
    }

    private addError(field: string, message: string, code: string, suggestion?: string): void {
        this.errors.push({ field, message, code, suggestion });
    }

    private addWarning(field: string, message: string, suggestion?: string): void {
        this.warnings.push({ field, message, suggestion });
    }

    /**
     * Get validation result
     */
    getResult<T>(data?: T): ValidationResult<T> {
        return {
            success: this.errors.length === 0,
            data,
            errors: [...this.errors],
            warnings: [...this.warnings]
        };
    }

    /**
     * Reset validator state
     */
    reset(): this {
        this.errors = [];
        this.warnings = [];
        return this;
    }

    /**
     * Format validation errors and warnings for display
     */
    formatMessages(): string {
        const messages: string[] = [];

        if (this.errors.length > 0) {
            messages.push('❌ **Validation Errors:**');
            for (const error of this.errors) {
                messages.push(`- **${error.field}**: ${error.message}`);
                if (error.suggestion) {
                    messages.push(`  💡 *Suggestion: ${error.suggestion}*`);
                }
            }
        }

        if (this.warnings.length > 0) {
            if (messages.length > 0) messages.push('');
            messages.push('⚠️ **Validation Warnings:**');
            for (const warning of this.warnings) {
                messages.push(`- **${warning.field}**: ${warning.message}`);
                if (warning.suggestion) {
                    messages.push(`  💡 *Suggestion: ${warning.suggestion}*`);
                }
            }
        }

        return messages.join('\n');
    }
}

/**
 * Comprehensive input validation function
 */
export function validateInputs(inputs: {
    files: string[];
    thresholds?: string;
    groups?: string;
    timeoutSeconds: number;
    maxBytesPerFile: number;
    maxTotalBytes: number;
    gistId?: string;
    gistToken?: string;
}): ValidationResult<typeof inputs> {
    const validator = new EnhancedValidator();

    const result = validator
        .validateFiles(inputs.files)
        .validateThresholds(inputs.thresholds)
        .validateGroups(inputs.groups)
        .validateLimits(inputs.timeoutSeconds, inputs.maxBytesPerFile, inputs.maxTotalBytes)
        .validateGitHubSettings(inputs.gistId, inputs.gistToken)
        .getResult(inputs);

    return result;
}
