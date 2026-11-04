#!/bin/sh
set -eu

expect_channel() {
    tag=$1
    expected=$2
    actual=$(sh scripts/release-channel.sh "$tag")
    test "$actual" = "prerelease=$expected" || {
        echo "$tag: expected prerelease=$expected, got $actual" >&2
        exit 1
    }
}

expect_channel v0.7.0 true
expect_channel v0.8.0-rc.1 true
expect_channel v1.0.0 false
expect_channel v1.1.0-beta.2 true
expect_channel v10.0.0 false

if sh scripts/release-channel.sh 1.0.0 >/dev/null 2>&1; then
    echo "tag without v prefix was accepted" >&2
    exit 1
fi

echo "Release channel classification passed"
