#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
project_root="$(dirname -- "$script_dir")"
dist_dir="$project_root/dist"
echo "Project root: $project_root"
echo "Scripts in: $script_dir"
echo "Artifacts in: $dist_dir"

export SOURCE_DATE_EPOCH="$(git log -1 --format=%cd --date=unix)"
source_date_iso="$(date --utc --date="@$SOURCE_DATE_EPOCH" -Iseconds)"
echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH ($source_date_iso)"

version="$($script_dir/version.sh)"
dist_name="pgpvis-$version"
echo "Building $dist_name"

echo "============================================================"
echo "Rust toolchain:"
rustup show -v
echo "============================================================"

mkdir -p "$dist_dir"
pnpm clean
VITE_PGPVIS_VERSION="$version" pnpm dist

echo "============================================================"
dir_to_tar="$project_root/pgpvis-ui/dist"
tar_file="$dist_dir/$dist_name.tar.gz"

echo "Tarring $dir_to_tar"
# https://reproducible-builds.org/docs/archives/
tar cfvz "$tar_file" \
    --transform="s|${dir_to_tar#/}|$dist_name|" \
    --show-transformed-names \
    --mtime="$source_date_iso" \
    --sort=name \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --format=gnu \
    "$dir_to_tar"
echo "Tar created at $tar_file"
