#!/usr/bin/env bash

set -euo pipefail

FORMULA_NAME="dns-benchmark"
TAP_REPO="taihen/homebrew-tap"
TAG_NAME="${TAG_NAME:-${1:-}}"
TAP_TOKEN="${TAP_TOKEN:-}"
REPO="${GITHUB_REPOSITORY:-taihen/dns-benchmark}"

if [[ -z "${TAG_NAME}" ]]; then
  echo "TAG_NAME is required" >&2
  exit 1
fi

if [[ -z "${TAP_TOKEN}" ]]; then
  echo "TAP_TOKEN is required" >&2
  exit 1
fi

OWNER="${REPO%/*}"
REPO_NAME="${REPO#*/}"
URL="https://github.com/${OWNER}/${REPO_NAME}/archive/refs/tags/${TAG_NAME}.tar.gz"
SHA256="$(curl -fsSL "${URL}" | shasum -a 256 | awk '{print $1}')"
VERSION_TRIMMED="${TAG_NAME#v}"

work_dir="$(mktemp -d)"
tap_dir="${work_dir}/tap"

cleanup() {
  rm -rf "${work_dir}"
}

trap cleanup EXIT

git clone "https://x-access-token:${TAP_TOKEN}@github.com/${TAP_REPO}.git" "${tap_dir}"
mkdir -p "${tap_dir}/Formula"

# Prefer a local formula template when one exists in this repo.
if [[ -f "Formula/${FORMULA_NAME}.rb" ]]; then
  cp "Formula/${FORMULA_NAME}.rb" "${tap_dir}/Formula/${FORMULA_NAME}.rb"
elif [[ ! -f "${tap_dir}/Formula/${FORMULA_NAME}.rb" ]]; then
  echo "Formula/${FORMULA_NAME}.rb not found locally or in ${TAP_REPO}" >&2
  exit 1
fi

sed -i.bak -E \
  -e "s|^(\\s*url\\s+\").*\"|\\1${URL}\"|" \
  -e "s|^(\\s*sha256\\s+\").*\"|\\1${SHA256}\"|" \
  -e "s|^(\\s*version\\s+\").*\"|\\1${VERSION_TRIMMED}\"|" \
  "${tap_dir}/Formula/${FORMULA_NAME}.rb" || true
rm -f "${tap_dir}/Formula/${FORMULA_NAME}.rb.bak"

cd "${tap_dir}"
git add "Formula/${FORMULA_NAME}.rb"

if git diff --cached --quiet; then
  echo "No changes to commit."
  exit 0
fi

GIT_AUTHOR_NAME="dns-benchmark-bot" \
GIT_AUTHOR_EMAIL="dns-benchmark@users.noreply.github.com" \
GIT_COMMITTER_NAME="dns-benchmark-bot" \
GIT_COMMITTER_EMAIL="dns-benchmark@users.noreply.github.com" \
git commit -m "${FORMULA_NAME} ${TAG_NAME}: update formula url and sha256"
git push origin HEAD:main
