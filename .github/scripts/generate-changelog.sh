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

# Add installation section for HTTP client
echo "### 📦 Installation"
echo ""
echo "Download the appropriate binary for your platform from the assets below:"
echo ""
echo "**Linux:**"
echo "- \`azuretls-cffi-linux-amd64.tar.gz\` - 64-bit Intel/AMD"
echo "- \`azuretls-cffi-linux-arm64.tar.gz\` - 64-bit ARM"
echo "- \`azuretls-cffi-linux-386.tar.gz\` - 32-bit Intel/AMD"
echo "- \`azuretls-cffi-linux-arm.tar.gz\` - 32-bit ARM"
echo ""
echo "**Windows:**"
echo "- \`azuretls-cffi-windows-amd64.zip\` - 64-bit Intel/AMD"
echo "- \`azuretls-cffi-windows-386.zip\` - 32-bit Intel/AMD"
echo "- \`azuretls-cffi-windows-arm64.zip\` - 64-bit ARM"
echo ""
echo "**macOS:**"
echo "- \`azuretls-cffi-darwin-amd64.tar.gz\` - Intel Macs"
echo "- \`azuretls-cffi-darwin-arm64.tar.gz\` - Apple Silicon Macs"
echo ""
echo "**FreeBSD:**"
echo "- \`azuretls-cffi-freebsd-amd64.tar.gz\` - 64-bit Intel/AMD"
echo "- \`azuretls-cffi-freebsd-arm64.tar.gz\` - 64-bit ARM"
echo ""

# Add full changelog link
if [ ! -z "$GITHUB_REPOSITORY" ]; then
    echo "**Full Changelog**: https://github.com/$GITHUB_REPOSITORY/compare/$PREVIOUS_TAG...$CURRENT_TAG"
fi