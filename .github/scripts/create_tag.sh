#!/bin/bash
set -e

VERSION="$1"
TAG="v$VERSION"

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"
git tag -a "$TAG" -m "Release $TAG"
git push origin "$TAG"
