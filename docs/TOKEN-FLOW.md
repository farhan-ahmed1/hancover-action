# Token & Gist Flow Explanation

## 🔐 How Tokens and Gist IDs Flow Through the System

### 1. User Setup (One Time)
```bash
# User creates secrets in their repo
COVERAGE_GIST_ID = "abc123def456789"
GIST_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"
```

### 2. Workflow File (User's Repo)
```yaml
# In user's .github/workflows/coverage.yml
- name: Coverage Report
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    gist-id: ${{ secrets.COVERAGE_GIST_ID }}     # ← Injects "abc123def456789"
    github-token: ${{ secrets.GIST_TOKEN }}      # ← Injects "ghp_xxxxxxxxxxxx"
```

### 3. Action Inputs (action.yml)
```yaml
# In our action.yml
inputs:
  gist-id:
    description: "GitHub Gist ID for storing coverage data"
    required: false
  github-token:
    description: "GitHub token for API access"
    required: false
```

### 4. Input Reading (inputs.ts)
```typescript
// In our src/inputs.ts
export function readInputs(): ActionInputs {
    const raw = {
        // ...other inputs...
        gistId: process.env['INPUT_GIST-ID']          // ← Gets "abc123def456789"
    };
    
    return { ...parsed, gistId: raw.gistId };
}
```

### 5. Coverage Data Module (coverage-data.ts)
```typescript
// In our src/coverage-data.ts
export async function getCoverageData(): Promise<number | null> {
    const gistId = core.getInput('gist-id');          // ← Gets "abc123def456789"
    const token = core.getInput('github-token') ||    // ← Gets "ghp_xxxxxxxxxxxx"
                  process.env.GITHUB_TOKEN;
    
    if (!gistId || !token) return null;
    
    // Use GitHub API with these values
    const octokit = github.getOctokit(token);
    const { data } = await octokit.rest.gists.get({
        gist_id: gistId                               // ← Uses "abc123def456789"
    });
    
    // Extract coverage from gist files
    const coverageFile = data.files?.['coverage.json'];
    if (coverageFile?.content) {
        const coverageData = JSON.parse(coverageFile.content);
        return coverageData.coverage;                  // ← Returns 85.2
    }
    
    return null;
}
```

### 6. Enhanced Module (enhanced.ts)
```typescript
// In our src/enhanced.ts
export async function runEnhancedCoverage() {
    // ...generate current PR coverage...
    const projectLinesPct = 87.1;
    
    // Get baseline coverage from gist
    const mainBranchCoverage = await getCoverageData();  // ← Returns 85.2
    
    if (mainBranchCoverage !== null) {
        const delta = projectLinesPct - mainBranchCoverage;  // 87.1 - 85.2 = +1.9
        
        // Generate badges with delta
        const changesBadge = `![Changes](https://img.shields.io/badge/changes-+${delta.toFixed(1)}%25-brightgreen)`;
    }
    
    // If on main branch, save new baseline
    if (isMainBranch) {
        await saveCoverageData(projectLinesPct);  // ← Saves 87.1 to gist
    }
}
```

## 🎯 Key Points for Users

### ✅ What Users Need to Do:
1. **Create a public gist** with initial `coverage.json` file
2. **Create a personal access token** with `gist` scope  
3. **Add two secrets** to their repository:
   - `COVERAGE_GIST_ID`: The gist ID
   - `GIST_TOKEN`: The personal access token
4. **Use these secrets in workflow** files with our action

### ✅ What Our Action Handles Automatically:
1. **Reading the secrets** from workflow inputs
2. **Authenticating with GitHub API** using the token
3. **Fetching baseline coverage** from the specified gist
4. **Calculating coverage deltas** between PR and main
5. **Updating the gist** with new coverage data
6. **Generating badge JSON** in Shields.io format

### 🔄 The Complete Data Flow:

```
User's Repo Secrets  →  Workflow File  →  Action Inputs  →  Our Code  →  GitHub API  →  Gist
     ↓                      ↓                 ↓              ↓            ↓           ↓
COVERAGE_GIST_ID    →   gist-id: ${{...}} → INPUT_GIST-ID → getInput() → gist.get() → Read
GIST_TOKEN          →   github-token: ${{...}} → INPUT_GITHUB-TOKEN → getInput() → authenticate → Write
```

This design means users only need to:
- Set up a gist once
- Add two secrets to their repo  
- Copy our workflow files

Everything else is handled automatically by our action! 🎉
