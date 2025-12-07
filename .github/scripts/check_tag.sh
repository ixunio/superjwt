#!/bin/bash
set -e

VERSION="$1"
TAG="v$VERSION"

if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "exists=true" >> $GITHUB_OUTPUT
  echo "Tag $TAG already exists"
else
  echo "exists=false" >> $GITHUB_OUTPUT
  echo "Tag $TAG does not exist"
fi
