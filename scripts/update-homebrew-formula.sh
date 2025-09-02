#!/bin/bash

# Script to automatically update Homebrew formula for dns-benchmark
# This should be run after each release

set -e

# Configuration
REPO="taihen/dns-benchmark"
FORMULA_NAME="dns-benchmark"

# Get the latest release version
LATEST_VERSION=$(gh release list --repo $REPO --limit 1 --json tagName --jq '.[0].tagName' | sed 's/v//')

if [ -z "$LATEST_VERSION" ]; then
    echo "Error: Could not get latest release version"
    exit 1
fi

echo "Latest version: $LATEST_VERSION"

# Download the release assets to get SHA256 checksums
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download macOS binaries
gh release download --repo $REPO --pattern "dns-benchmark-darwin-*" --dir "$TEMP_DIR"

# Calculate SHA256 checksums
ARM64_SHA=$(shasum -a 256 dns-benchmark-darwin-arm64 | cut -d' ' -f1)
AMD64_SHA=$(shasum -a 256 dns-benchmark-darwin-amd64 | cut -d' ' -f1)

echo "ARM64 SHA256: $ARM64_SHA"
echo "AMD64 SHA256: $AMD64_SHA"

# Create the updated formula
cat > "${FORMULA_NAME}.rb" << FORMULA_EOF
class DnsBenchmark < Formula
  desc "DNS benchmark tool that tests DNS resolver performance across multiple protocols"
  homepage "https://github.com/taihen/dns-benchmark"
  url "https://github.com/taihen/dns-benchmark/releases/download/v${LATEST_VERSION}/dns-benchmark-darwin-arm64"
  sha256 "${ARM64_SHA}"
  license "MIT"
  head "https://github.com/taihen/dns-benchmark.git", branch: "main"

  on_intel do
    url "https://github.com/taihen/dns-benchmark/releases/download/v${LATEST_VERSION}/dns-benchmark-darwin-amd64"
    sha256 "${AMD64_SHA}"
  end

  def install
    # Install the binary directly from the release
    bin.install "dns-benchmark-darwin-\#{Hardware::CPU.arch}" => "dns-benchmark"
  end

  test do
    # Test that the binary runs and shows version
    assert_match "dns-benchmark", shell_output("\#{bin}/dns-benchmark --version")
  end
end
FORMULA_EOF

echo "Updated formula created: ${FORMULA_NAME}.rb"
echo "Next steps:"
echo "1. Create Formula directory in your repository: mkdir -p Formula"
echo "2. Copy this formula: cp ${FORMULA_NAME}.rb Formula/"
echo "3. Commit and push the changes"

# Clean up
cd - > /dev/null
rm -rf "$TEMP_DIR"
