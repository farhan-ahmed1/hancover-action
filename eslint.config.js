import globals from 'globals';
import tsParser from '@typescript-eslint/parser';

export default [
    // TypeScript files: use the TypeScript parser
    {
        files: ['src/**/*.{ts,tsx}', 'test/**/*.{ts,tsx}'],
        languageOptions: {
            parser: tsParser,
            globals: {
                ...globals.browser,
                ...globals.es2021,
            },
            parserOptions: {
                ecmaVersion: 2021,
                sourceType: 'module',
                project: './tsconfig.json',
            },
        },
        rules: {
            'no-console': 'warn',
            'no-unused-vars': 'warn',
            'indent': ['error', 4],
            'quotes': ['error', 'single'],
            'semi': ['error', 'always'],
        },
    },

    // JavaScript files: use default parser
    {
        files: ['src/**/*.{js}', 'test/**/*.{js}'],
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.es2021,
            },
            parserOptions: {
                ecmaVersion: 2021,
                sourceType: 'module',
            },
        },
        rules: {
            'no-console': 'warn',
            'no-unused-vars': 'warn',
            'indent': ['error', 4],
            'quotes': ['error', 'single'],
            'semi': ['error', 'always'],
        },
    },
];

export const ignores = [
    'node_modules/**',
    'dist/**',
    'build/**',
    '*.min.js',
    '*.bundle.js',
    '**/*.map',
    '*.log',
    '.DS_Store',
    'coverage/**',
];