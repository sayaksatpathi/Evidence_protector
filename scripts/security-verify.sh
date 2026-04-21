#!/bin/bash
# Security Verification Script - Run before pushing to production
# Ensures no sensitive data is exposed in the repository

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔐 Evidence Protector - Security Verification"
echo "=============================================="
echo ""

violations=0

# Check 1: No .env files committed (except .example)
echo "✓ Checking for .env files..."
if git ls-files | grep -E '\.env$|\.env\.[^e]' | grep -v "\.example$" > /dev/null 2>&1; then
    echo -e "${RED}✗ FOUND .env files in repository!${NC}"
    git ls-files | grep -E '\.env$|\.env\.[^e]' | grep -v "\.example$"
    ((violations++))
else
    echo -e "${GREEN}✓ No .env files (only .example files allowed)${NC}"
fi

# Check 2: No private keys
echo "✓ Checking for private keys..."
if git ls-files | grep -iE '\.(pem|key|p12|jks)$' | grep -v "\.example" > /dev/null 2>&1; then
    echo -e "${RED}✗ FOUND private key files in repository!${NC}"
    git ls-files | grep -iE '\.(pem|key|p12|jks)$'
    ((violations++))
else
    echo -e "${GREEN}✓ No private key files${NC}"
fi

# Check 3: No hardcoded credentials
echo "✓ Checking for hardcoded credentials..."
if git ls-files '*.py' | xargs grep -l -E "=['\"][a-zA-Z0-9_-]{32,}['\"]" 2>/dev/null | grep -v "test_\|\.example" > /dev/null 2>&1; then
    echo -e "${RED}✗ Found hardcoded credentials!${NC}"
    ((violations++))
else
    echo -e "${GREEN}✓ No hardcoded credentials${NC}"
fi

# Check 4: .gitignore properly configured
echo "✓ Checking .gitignore configuration..."
if grep -q "\.env" .gitignore 2>/dev/null && grep -qE '\*\.pem|\*\.key' .gitignore 2>/dev/null; then
    echo -e "${GREEN}✓ .gitignore properly configured${NC}"
else
    echo -e "${RED}✗ .gitignore missing critical patterns${NC}"
    ((violations++))
fi

# Summary
echo ""
echo "=============================================="
if [ $violations -eq 0 ]; then
    echo -e "${GREEN}✅ ALL SECURITY CHECKS PASSED${NC}"
    echo ""
    echo "Safe to push to repository!"
    exit 0
else
    echo -e "${RED}❌ SECURITY VIOLATIONS FOUND: $violations${NC}"
    echo ""
    echo "Do not push until issues are resolved!"
    exit 1
fi

