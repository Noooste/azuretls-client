#!/bin/bash

# Generate changelog between two git tags
# Usage: ./generate-changelog.sh <previous_tag> <current_tag>

set -e

PREVIOUS_TAG="$1"
CURRENT_TAG="$2"

if [ -z "$PREVIOUS_TAG" ] || [ -z "$CURRENT_TAG" ]; then
    echo "Usage: $0 <previous_tag> <current_tag>"
    exit 1
fi

echo "## What's Changed"
echo ""

# Get commits between tags, excluding merge commits
COMMITS=$(git log --pretty=format:"* %s" "$PREVIOUS_TAG..$CURRENT_TAG" \
    --grep="Merge pull request" --invert-grep \
    --grep="Merge branch" --invert-grep \
    | head -30)

# Categorize commits
FEATURES=""
FIXES=""
OTHER=""

if [ ! -z "$COMMITS" ]; then
    while IFS= read -r line; do
        if [[ $line == *"feat"* ]] || [[ $line == *"add"* ]] || [[ $line == *"implement"* ]] || [[ $line == *"new"* ]]; then
            if [ -z "$FEATURES" ]; then
                FEATURES="$line"
            else
                FEATURES="$FEATURES"$'\n'"$line"
            fi
        elif [[ $line == *"fix"* ]] || [[ $line == *"bug"* ]] || [[ $line == *"resolve"* ]] || [[ $line == *"patch"* ]]; then
            if [ -z "$FIXES" ]; then
                FIXES="$line"
            else
                FIXES="$FIXES"$'\n'"$line"
            fi
        else
            if [ -z "$OTHER" ]; then
                OTHER="$line"
            else
                OTHER="$OTHER"$'\n'"$line"
            fi
        fi
    done <<< "$COMMITS"
fi

# Output categorized changes
if [ ! -z "$FEATURES" ]; then
    echo "### 🚀 Features & Improvements"
    echo ""
    echo "$FEATURES"
    echo ""
fi

if [ ! -z "$FIXES" ]; then
    echo "### 🐛 Bug Fixes"
    echo ""
    echo "$FIXES"
    echo ""
fi

if [ ! -z "$OTHER" ]; then
    echo "### 🔧 Other Changes"
    echo ""
    echo "$OTHER"
    echo ""
fi

# Get merged pull requests
PRS=$(git log --pretty=format:"%s" "$PREVIOUS_TAG..$CURRENT_TAG" \
    | grep "Merge pull request" \
    | sed -E 's/Merge pull request #([0-9]+) from .*/\1/' \
    | sort -n -u)


# Add pull requests section if there are any
if [ ! -z "$PRS" ]; then
    echo "### 📋 Pull Requests"
    echo ""
    for pr in $PRS; do
        # Try to get PR title from GitHub API if available
        if [ ! -z "$GITHUB_REPOSITORY" ] && command -v curl >/dev/null 2>&1; then
            PR_TITLE=$(curl -s -f "https://api.github.com/repos/$GITHUB_REPOSITORY/pulls/$pr" 2>/dev/null | grep '"title"' | head -1 | sed 's/.*"title": "\(.*\)",/\1/' || echo "")
            if [ ! -z "$PR_TITLE" ] && [ "$PR_TITLE" != "null" ]; then
                echo "* $PR_TITLE (#$pr)"
            else
                echo "* Pull request #$pr"
            fi
        else
            echo "* Pull request #$pr"
        fi
    done
    echo ""
fi

# Get unique contributors
CONTRIBUTORS=$(git log --pretty=format:"%an" "$PREVIOUS_TAG..$CURRENT_TAG" | sort -u)
if [ ! -z "$CONTRIBUTORS" ]; then
    echo "### 👥 Contributors"
    echo ""
    echo "$CONTRIBUTORS" | while IFS= read -r contributor; do
        echo "* @$contributor"
    done
    echo ""
fi

VERSION="${CURRENT_TAG#v}"

# Add installation section for HTTP client
echo "### 📦 Installation"
echo ""
echo "Download the appropriate binary for your platform from the assets below:"
echo ""
echo "**Linux:**"
echo "- \`azuretls-${VERSION}-linux-amd64.so\` - 64-bit Intel/AMD"
echo "- \`azuretls-${VERSION}-linux-arm64.so\` - 64-bit ARM"
echo "- \`azuretls-${VERSION}-linux-386.so\` - 32-bit Intel/AMD"
echo "- \`azuretls-${VERSION}-linux-arm.so\` - 32-bit ARM"
echo ""
echo "**Windows:**"
echo "- \`azuretls-${VERSION}-windows-amd64.dll\` - 64-bit Intel/AMD"
echo "- \`azuretls-${VERSION}-windows-386.dll\` - 32-bit Intel/AMD"
echo ""
echo "**macOS:**"
echo "- \`azuretls-${VERSION}-darwin-amd64.dylib\` - Intel Macs"
echo "- \`azuretls-${VERSION}-darwin-arm64.dylib\` - Apple Silicon Macs"
echo ""

# Add full changelog link
if [ ! -z "$GITHUB_REPOSITORY" ]; then
    echo "**Full Changelog**: https://github.com/$GITHUB_REPOSITORY/compare/$PREVIOUS_TAG...$CURRENT_TAG"
fi