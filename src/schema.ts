export type LineCov = { line: number; hits: number; isBranch?: boolean; branchesHit?: number; branchesTotal?: number };
export type FileCov = {
  path: string;
  lines: LineCov[];
  summary: { linesCovered: number; linesTotal: number; branchesCovered?: number; branchesTotal?: number };
  package?: string;
};
export type CoverageBundle = { files: FileCov[] };
export type GroupRule = { name: string; include: string | string[]; exclude?: string | string[] };
export type GroupsConfig = GroupRule[];