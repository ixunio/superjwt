#!/bin/bash
set -e

VERSION="$1"

if [ -z "$VERSION" ]; then
  echo "Error: Version argument is required"
  exit 1
fi

# 1. Extract content (skipping the header line)
CHANGELOG=$(awk -v ver="## v$VERSION" 'index($0, ver) == 1 {flag=1; next} /^## / && index($0, ver) != 1 {if (flag) exit} flag' CHANGELOG.md)

# Fail if no changelog entry exists
if [ -z "$CHANGELOG" ]; then
  echo "❌ ERROR: No changelog entry found for version $VERSION"
  echo "Please add a changelog entry in CHANGELOG.md before releasing"
  echo ""
  echo "Expected format:"
  echo "## v$VERSION (YYYY-MM-DD)"
  echo ""
  echo "### Changes"
  echo "- Your changes here"
  exit 1
fi

# Use EOF delimiter for multiline output
echo "content<<EOF" >> $GITHUB_OUTPUT
echo "$CHANGELOG" >> $GITHUB_OUTPUT
echo "EOF" >> $GITHUB_OUTPUT

# 2. Extract the date (format: YYYY-MM-DD)
RELEASE_DATE=$(grep "^## v$VERSION" CHANGELOG.md | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)

# Fail if no date found
if [ -z "$RELEASE_DATE" ]; then
  echo "❌ ERROR: Could not extract date from changelog header for version $VERSION"
  echo "Expected format: ## v$VERSION (YYYY-MM-DD)"
  exit 1
fi

# Format date to "Dec 06, 2025"
FORMATTED_DATE=$(date -d "$RELEASE_DATE" "+%b %d, %Y")
echo "release_date=$FORMATTED_DATE" >> $GITHUB_OUTPUT
