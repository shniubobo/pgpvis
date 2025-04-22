#!/usr/bin/env bash
set -euo pipefail

git_output="$(git describe --tags --abbrev=7 --match='v*' --dirty --always)"
pattern='^((v[0-9]+\.[0-9]+\.[0-9])(-([0-9]+)-g([0-9a-z]{7}))?(-(dirty))?)|([0-9a-z]{7})(-(dirty))?$'
if ! [[ $git_output =~ $pattern ]]; then
    exit 1
fi

if [[ ${BASH_REMATCH[1]} ]]; then
    # Tag found
    version="${BASH_REMATCH[2]}"
    commit_n="${BASH_REMATCH[4]}"
    commit_id="${BASH_REMATCH[5]}"
    dirty="${BASH_REMATCH[7]}"
else
    # Tag not found
    version="v0.0.0"
    commit_n="0"
    commit_id="${BASH_REMATCH[8]}"
    dirty="${BASH_REMATCH[10]}"
fi

if [[ $dirty && $commit_id ]]; then
    # v0.1.0+1.012abcd.dirty or v0.0.0+0.012abcd.dirty
    echo "$version+$commit_n.$commit_id.$dirty"
elif [[ $commit_id ]]; then
    # v0.1.0+1.012abcd or v0.0.0+0.012abcd
    echo "$version+$commit_n.$commit_id"
elif [[ $dirty ]]; then
    # v0.1.0+dirty
    echo "$version+$dirty"
elif [[ $version ]]; then
    # v0.1.0
    echo "$version"
else
    exit 1
fi
