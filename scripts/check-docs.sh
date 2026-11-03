#!/bin/sh
set -eu
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
cargo run --quiet -p dich-cli --bin dich-gen-docs -- "$out"
test -s "$out/man/dich.1"
test -s "$out/completions/dich.bash"
test -s "$out/completions/_dich"
test -s "$out/completions/dich.fish"
for command in update search show versions plan fetch inspect install remove rollback store profile sources gc; do
    test -s "$out/man/dich-$command.1"
    for completion in dich.bash _dich dich.fish; do
        grep -Fq "$command" "$out/completions/$completion"
    done
done
for page in dich-store-ls dich-store-verify dich-profile-list dich-sources-list; do
    test -s "$out/man/$page.1"
done
grep -Fq 'EXACT_VERSION' "$out/man/dich-fetch.1"
grep -Fq 'COMPONENT' "$out/man/dich-fetch.1"
grep -Fq 'KIND' "$out/man/dich-store-verify.1"
for completion in dich.bash _dich dich.fish; do
    grep -Fq 'verify' "$out/completions/$completion"
    grep -Fq 'exact-version' "$out/completions/$completion"
    grep -Fq 'publish-tree' "$out/completions/$completion"
done
if command -v bash >/dev/null 2>&1; then
    bash -n "$out/completions/dich.bash"
fi
echo "Documentation assets generated successfully"
