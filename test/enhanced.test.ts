import { parseLCOV } from '../src/parsers/lcov.js';
import { groupPackages } from '../src/group.js';
import { computeChangesCoverage, parseGitDiff } from '../src/changes.js';
import { renderComment } from '../src/comment.js';

describe('Enhanced Coverage System', () => {
    test('can parse LCOV and create comment', async () => {
        const sampleLcov = `TN:
SF:src/example.ts
FN:1,exampleFunction
FNDA:5,exampleFunction
FNF:1
FNH:1
DA:1,5
DA:2,3
DA:3,0
LF:3
LH:2
BRF:0
BRH:0
end_of_record
`;

        const project = parseLCOV(sampleLcov);
        expect(project.files).toHaveLength(1);
        expect(project.files[0].path).toBe('src/example.ts');
        expect(project.files[0].lines.covered).toBe(2);
        expect(project.files[0].lines.total).toBe(3);
        expect(project.files[0].functions.covered).toBe(1);
        expect(project.files[0].functions.total).toBe(1);

        const packages = groupPackages(project.files);
        expect(packages).toHaveLength(1);
        expect(packages[0].name).toBe('src');

        const changesCoverage = computeChangesCoverage(project, {
            'src/example.ts': new Set([1, 2])
        });

        expect(changesCoverage.totals.lines.covered).toBe(2);
        expect(changesCoverage.totals.lines.total).toBe(2);

        const comment = await renderComment({
            prProject: project,
            prPackages: packages,
            changesCoverage,
            minThreshold: 50
        });

        expect(comment).toContain('Code Coverage');
        expect(comment).toContain('Project Coverage (PR)');
        expect(comment).toContain('Code Changes Coverage');
    });

    test('can parse git diff', () => {
        const gitDiff = `diff --git a/src/file1.ts b/src/file1.ts
index abc123..def456 100644
--- a/src/file1.ts
+++ b/src/file1.ts
@@ -10,0 +11,3 @@ export function example() {
+  const newLine1 = true;
+  const newLine2 = false;
+  return newLine1 && newLine2;
`;

        const result = parseGitDiff(gitDiff);
        expect(result['src/file1.ts']).toEqual(new Set([11, 12, 13]));
    });
});
