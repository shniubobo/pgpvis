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
# Can't understand why GPG only allows this format when it says it accepts
# "ISO time string" 😅
source_date_gpg="$(date --utc --date="@$SOURCE_DATE_EPOCH" +%Y%m%dT%H%M%SZ)"
echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH ($source_date_gpg)"

version="$($script_dir/version.sh)"
dist_name="pgpvis-$version"
tar_file="$dist_dir/$dist_name.tar.gz"
echo "Signing $tar_file"
echo "============================================================"

if [[ ! -f $tar_file ]]; then
    echo "$tar_file does not exist. Download from CI and place it in $dist_dir"
    exit 1
fi

echo "Signing using the default key"
sig="$(
    gpg \
    --faked-system-time "$source_date_gpg!" \
    --output - \
    --armor \
    --detach-sig \
    "$tar_file"
)"

object_hash="$(echo "$sig" | git hash-object -w --stdin)"
echo "Written signature to blob $object_hash"

ref_name="refs/sigs/$version"
echo "Making a reference at $ref_name"
git update-ref "$ref_name" "$object_hash"

echo "To view the signature: git cat-file blob $ref_name"
echo "To push the signature: git push <remote> $ref_name"
