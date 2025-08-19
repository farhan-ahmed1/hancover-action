#!/bin/bash

# Security audit script for HanCover Action
# This script performs various security checks

set -e

echo "🔒 Running HanCover Security Audit..."

# Check for high-severity vulnerabilities
echo "📦 Checking for npm vulnerabilities..."
npm audit --audit-level high

# Check for outdated dependencies with security issues
echo "📅 Checking for outdated dependencies..."
npm outdated || true

# Verify no hardcoded secrets in code
echo "🔍 Scanning for potential secrets..."
if command -v git &> /dev/null; then
    # Look for common secret patterns
    git grep -i "password\|secret\|key\|token" -- "*.ts" "*.js" "*.json" "*.yml" "*.yaml" || echo "No potential secrets found in tracked files"
fi

# Check file permissions
echo "🛡️ Checking file permissions..."
find . -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

# Verify action.yml structure
echo "⚙️ Validating action.yml..."
if [ -f "action.yml" ]; then
    # Basic validation that required fields exist
    grep -q "name:" action.yml && echo "✅ Action name present"
    grep -q "description:" action.yml && echo "✅ Action description present"
    grep -q "runs:" action.yml && echo "✅ Action runtime configuration present"
else
    echo "❌ action.yml not found"
    exit 1
fi

# Check for security-related files
echo "📋 Checking security documentation..."
[ -f "SECURITY.md" ] && echo "✅ SECURITY.md present" || echo "❌ SECURITY.md missing"
[ -f "LICENSE" ] && echo "✅ LICENSE present" || echo "❌ LICENSE missing"

# Check GitHub workflows
echo "🔄 Checking GitHub workflows..."
if [ -d ".github/workflows" ]; then
    [ -f ".github/workflows/codeql.yml" ] && echo "✅ CodeQL workflow present" || echo "❌ CodeQL workflow missing"
    [ -f ".github/workflows/scorecard.yml" ] && echo "✅ Scorecard workflow present" || echo "❌ Scorecard workflow missing"
fi

# Check for minimal permissions in workflows
echo "🔐 Checking workflow permissions..."
if [ -d ".github/workflows" ]; then
    for workflow in .github/workflows/*.yml; do
        if grep -q "permissions:" "$workflow"; then
            echo "✅ $workflow has permissions defined"
        else
            echo "⚠️ $workflow may need explicit permissions"
        fi
    done
fi

echo "✅ Security audit completed!"
