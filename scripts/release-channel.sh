#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: release-channel.sh vX.Y.Z[-prerelease]" >&2
    exit 2
fi

tag=$1
case "$tag" in
    v*) version=${tag#v} ;;
    *) echo "release tag must start with v" >&2; exit 2 ;;
esac

# Keep every 0.x release experimental until v1, and every SemVer prerelease
# experimental regardless of major version. The release workflow separately
# requires an exact match with dich-cli's Cargo package version.
case "$version" in
    0.*|*-*) prerelease=true ;;
    *) prerelease=false ;;
esac

printf 'prerelease=%s\n' "$prerelease"
