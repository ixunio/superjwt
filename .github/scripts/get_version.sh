#!/bin/bash
set -e

VERSION=$(python -c "import sys; sys.path.insert(0, 'superjwt'); from _version import __version__; print(__version__)")
echo "version=$VERSION" >> $GITHUB_OUTPUT
echo "Current version: $VERSION"
