# Changes Badge Setup

The changes badge shows the coverage delta between your PR and the main branch using a simple JSON file stored in your repository.

## How It Works

1. **Main Branch**: When running on the main branch, the action updates a JSON file with the current coverage percentage
2. **PR Branches**: When running on PRs, the action reads the JSON file to get the main branch coverage and calculates the delta
3. **Badge Display**: Shows a visual badge with the coverage change (e.g., `+2.1%` or `-1.5%`)

## Setup

The changes badge compares your PR's coverage against the main branch coverage and displays a delta (e.g., `+2.3%` or `-1.1%`). This provides immediate visual feedback on whether your changes improve or decrease code coverage.

## Setup Steps

### 1. Create a Shields JSON Endpoint

You need to create a publicly accessible JSON endpoint that stores your main branch coverage. This can be:

- **GitHub Gist** (recommended for simplicity)
- **GitHub Pages**
- **Your own server/CDN**

#### Option A: GitHub Gist (Recommended)

1. Create a new **public** gist at https://gist.github.com
2. Create a file named `coverage.json` with initial content:
   ```json
   {
     "schemaVersion": 1,
     "label": "coverage",
     "message": "0.0%",
     "color": "red",
     "coverage": 0,
     "timestamp": "2025-01-01T00:00:00.000Z"
   }
   ```
3. Get the raw URL of your gist file (it will look like):
   ```
   https://gist.githubusercontent.com/username/gist-id/raw/coverage.json
   ```

#### Option B: GitHub Pages

1. Create a `docs/` folder in your repository
2. Add a `coverage.json` file with the same content as above
3. Enable GitHub Pages for the `docs/` folder
4. Your endpoint will be:
   ```
   https://username.github.io/repository/coverage.json
   ```

### 2. Update Your Workflow

Add the `shields-endpoint-url` input to your workflow:

```yaml
- name: Coverage Report
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    shields-endpoint-url: https://gist.githubusercontent.com/username/gist-id/raw/coverage.json
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### 3. Update Your Main Branch Coverage

When running on the main branch, the action will automatically:
1. Generate shields JSON with the current coverage
2. Output it via the `shields-json` output

You need to set up a workflow step to update your endpoint:

#### For GitHub Gist:

```yaml
- name: Coverage Report
  id: coverage
  uses: farhan-ahmed1/hancover-action@v1
  with:
    files: coverage/lcov.info
    shields-endpoint-url: https://gist.githubusercontent.com/username/gist-id/raw/coverage.json
    github-token: ${{ secrets.GITHUB_TOKEN }}

- name: Update Coverage Gist
  if: github.ref == 'refs/heads/main'
  run: |
    echo '${{ steps.coverage.outputs.shields-json }}' > coverage.json
    curl -X PATCH \
      -H "Authorization: token ${{ secrets.GIST_TOKEN }}" \
      -H "Content-Type: application/json" \
      -d '{
        "files": {
          "coverage.json": {
            "content": "'"$(cat coverage.json | sed 's/"/\\"/g' | tr -d '\n')"'"
          }
        }
      }' \
      "https://api.github.com/gists/YOUR_GIST_ID"
```

#### For GitHub Pages:

```yaml
- name: Update Coverage Data
  if: github.ref == 'refs/heads/main'
  run: |
    echo '${{ steps.coverage.outputs.shields-json }}' > docs/coverage.json
    git config --local user.email "action@github.com"
    git config --local user.name "GitHub Action"
    git add docs/coverage.json
    git commit -m "Update coverage data" || exit 0
    git push
```

### 4. Required Secrets

For GitHub Gist updates, you'll need:
1. Create a Personal Access Token with `gist` scope
2. Add it as a repository secret named `GIST_TOKEN`

## Result

After setup, your PR comments will show:

```
[![Coverage](https://img.shields.io/badge/coverage-85.2%25-green)](#)
[![Changes](https://img.shields.io/badge/changes-%2B2.3%25-brightgreen)](#)
```

The changes badge will be:
- **Green** with `+X.X%` if coverage increased
- **Red** with `-X.X%` if coverage decreased
- **Hidden** if main branch coverage isn't available yet

## Troubleshooting

1. **Changes badge not showing**: Ensure your shields endpoint URL is correct and publicly accessible
2. **Wrong coverage values**: Make sure you're updating the endpoint when merging to main
3. **Rate limits**: GitHub Gist API has rate limits; consider using GitHub Pages for high-frequency updates

## Migration from Baseline Files

If you're currently using `baseline-files`, you can switch to this simpler approach:

1. Set up the shields endpoint as described above
2. Remove the `baseline-files` input from your workflow
3. Add the `shields-endpoint-url` input instead

The changes badge provides the same delta information but with a simpler setup and no need to store baseline files.
