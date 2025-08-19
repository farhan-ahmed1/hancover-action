export type LineCov = { line: number; hits: number; isBranch?: boolean; branchesHit?: number; branchesTotal?: number };

// New normalized types per implementation plan
export type FileCov = {
  path: string;
  lines: { covered: number; total: number };
  branches: { covered: number; total: number };
  functions: { covered: number; total: number };
  // For code-changes mapping:
  coveredLineNumbers: Set<number>; // where hits > 0
  // Legacy support
  lineCoverage?: LineCov[];
  summary?: { linesCovered: number; linesTotal: number; branchesCovered?: number; branchesTotal?: number };
  package?: string;
};

export type ProjectCov = {
  files: FileCov[];
  totals: { 
    lines: { covered: number; total: number };
    branches: { covered: number; total: number };
    functions: { covered: number; total: number };
  };
};

export type PkgCov = { 
  name: string; 
  files: FileCov[]; 
  totals: ProjectCov['totals'];
};

export type CoverageBundle = { files: FileCov[] };
export type GroupRule = { name: string; include: string | string[]; exclude?: string | string[] };
export type GroupsConfig = GroupRule[];