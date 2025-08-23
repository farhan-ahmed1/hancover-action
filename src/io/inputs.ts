import { z } from 'zod';
import YAML from 'yaml';
import { GroupsConfig } from '../processing/schema.js';

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
    coverageDataPath: z.string().optional().default('.github/coverage-data.json'),
    gistId: z.string().optional(),
    gistToken: z.string().optional()
});

// ActionInputs exposes `groups` as a parsed GroupsConfig (not raw string)
export type ActionInputs = Omit<z.infer<typeof InputsSchema>, 'groups' | 'baselineFiles'> & { 
    files: string[]; 
    groups?: GroupsConfig;
    baselineFiles?: string[];
};

export function readInputs(): ActionInputs {
    // Helper to read env with fallback between hyphenated and underscored names
    const env = (names: string[]): string | undefined => {
        for (const n of names) {
            const v = process.env[n];
            if (v !== undefined) return v;
        }
        return undefined;
    };

    const raw = {
        files: (process.env.INPUT_FILES ?? '').trim(),
        baseRef: env(['INPUT_BASE-REF', 'INPUT_BASE_REF']),
        thresholds: env(['INPUT_THRESHOLDS']),
        warnOnly: (env(['INPUT_WARN-ONLY', 'INPUT_WARN_ONLY']) ?? 'false') === 'true',
        commentMode: (env(['INPUT_COMMENT-MODE', 'INPUT_COMMENT_MODE']) ?? 'update') as 'update' | 'new',
        groups: env(['INPUT_GROUPS']),
        maxBytesPerFile: Number(env(['INPUT_MAX-BYTES-PER-FILE', 'INPUT_MAX_BYTES_PER_FILE']) ?? 52428800),
        maxTotalBytes: Number(env(['INPUT_MAX-TOTAL-BYTES', 'INPUT_MAX_TOTAL_BYTES']) ?? 209715200),
        timeoutSeconds: Number(env(['INPUT_TIMEOUT-SECONDS', 'INPUT_TIMEOUT_SECONDS']) ?? 120),
        strict: (env(['INPUT_STRICT']) ?? 'false') === 'true',
        baselineFiles: env(['INPUT_BASELINE-FILES', 'INPUT_BASELINE_FILES']),
        minThreshold: Number(env(['INPUT_MIN-THRESHOLD', 'INPUT_MIN_THRESHOLD']) ?? 50),
        gistId: env(['INPUT_GIST-ID', 'INPUT_GIST_ID']) || process.env.COVERAGE_GIST_ID || undefined,
        gistToken: env(['INPUT_GIST-TOKEN', 'INPUT_GIST_TOKEN']) || process.env.GIST_TOKEN || undefined
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
        gistId: raw.gistId,
        gistToken: raw.gistToken
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

    return { ...parsed, files, baselineFiles, groups: groupsParsed } as unknown as ActionInputs;
}
