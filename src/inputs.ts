import { z } from 'zod';
import YAML from 'yaml';
import { GroupsConfig } from './schema.js';

const InputsSchema = z.object({
    files: z.string().min(1),
    baseRef: z.string().optional(),
    thresholds: z.string().optional(),
    warnOnly: z.boolean().optional().default(false),
    commentMode: z.enum(['update', 'new']).optional().default('update'),
    groups: z.string().optional(),
    maxBytesPerFile: z.coerce.number().optional().default(52428800),
    maxTotalBytes: z.coerce.number().optional().default(209715200),
    timeoutSeconds: z.coerce.number().optional().default(120),
    strict: z.boolean().optional().default(false),
    baselineFiles: z.string().optional(),
    minThreshold: z.coerce.number().optional().default(50),
    coverageDataPath: z.string().optional().default('.github/coverage-data.json')
});

// ActionInputs exposes `groups` as a parsed GroupsConfig (not raw string)
export type ActionInputs = Omit<z.infer<typeof InputsSchema>, 'groups' | 'baselineFiles'> & { 
    files: string[]; 
    groups?: GroupsConfig;
    baselineFiles?: string[];
    coverageDataPath: string;
};

export function readInputs(): ActionInputs {
    const raw = {
        files: (process.env['INPUT_FILES'] ?? '').trim(),
        baseRef: process.env['INPUT_BASE-REF'],
        thresholds: process.env['INPUT_THRESHOLDS'],
        warnOnly: (process.env['INPUT_WARN-ONLY'] ?? 'false') === 'true',
        commentMode: (process.env['INPUT_COMMENT-MODE'] ?? 'update') as 'update' | 'new',
        groups: process.env['INPUT_GROUPS'],
        maxBytesPerFile: Number(process.env['INPUT_MAX-BYTES-PER-FILE'] ?? 52428800),
        maxTotalBytes: Number(process.env['INPUT_MAX-TOTAL-BYTES'] ?? 209715200),
        timeoutSeconds: Number(process.env['INPUT_TIMEOUT-SECONDS'] ?? 120),
        strict: (process.env['INPUT_STRICT'] ?? 'false') === 'true',
        baselineFiles: process.env['INPUT_BASELINE-FILES'],
        minThreshold: Number(process.env['INPUT_MIN-THRESHOLD'] ?? 50),
        coverageDataPath: process.env['INPUT_COVERAGE-DATA-PATH'] ?? '.github/coverage-data.json'
    };

    const parsed = InputsSchema.parse({
        files: raw.files || '',
        baseRef: raw.baseRef,
        thresholds: raw.thresholds,
        warnOnly: raw.warnOnly,
        commentMode: raw.commentMode,
        groups: raw.groups,
        maxBytesPerFile: raw.maxBytesPerFile,
        maxTotalBytes: raw.maxTotalBytes,
        timeoutSeconds: raw.timeoutSeconds,
        strict: raw.strict,
        baselineFiles: raw.baselineFiles,
        minThreshold: raw.minThreshold,
        coverageDataPath: raw.coverageDataPath
    });

    const files = (raw.files || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const baselineFiles = raw.baselineFiles 
        ? raw.baselineFiles.split(/\r?\n/).map(s => s.trim()).filter(Boolean)
        : undefined;

    // parse YAML groups if provided
    let groupsParsed: GroupsConfig | undefined = undefined;
    if (raw.groups) {
        try {
            const v = YAML.parse(raw.groups);
            groupsParsed = Array.isArray(v) ? (v as GroupsConfig) : undefined;
        } catch {
            groupsParsed = undefined;
        }
    }

    return { ...parsed, files, baselineFiles, groups: groupsParsed, coverageDataPath: raw.coverageDataPath } as unknown as ActionInputs;
}
