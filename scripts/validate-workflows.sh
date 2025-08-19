#!/bin/bash

# Workflow validation script
echo "🔍 Validating GitHub workflow files..."

# Check if all workflow files exist
workflows=("release.yml" "scorecard.yml" "security.yml" "codeql.yml" "ci.yml")

for workflow in "${workflows[@]}"; do
    file=".github/workflows/$workflow"
    if [[ -f "$file" ]]; then
        echo "✅ $workflow exists"
        
        # Basic syntax check - look for required fields
        if grep -q "name:" "$file" && grep -q "on:" "$file" && grep -q "jobs:" "$file"; then
            echo "✅ $workflow has required structure"
        else
            echo "❌ $workflow missing required fields (name, on, jobs)"
        fi
        
        # Check for permissions
        if grep -q "permissions:" "$file"; then
            echo "✅ $workflow has permissions defined"
        else
            echo "⚠️ $workflow may need explicit permissions"
        fi
        
    else
        echo "❌ $workflow missing"
    fi
    echo ""
done

echo "🎉 Workflow validation completed!"
