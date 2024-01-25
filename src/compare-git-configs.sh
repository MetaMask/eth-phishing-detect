#!/usr/bin/env bash

# USAGE: compare-git-configs.sh [base_ref:HEAD] [target_ref]

set -e

base_ref="${1:-$(git show-ref --head -s HEAD | head -c7)}"
target_ref=$2

oldcfg="$(mktemp)"
newcfg="$(mktemp)"

trap "rm -f '${oldcfg}' '${newcfg}'" EXIT

git show ${base_ref}:src/config.json    > ${oldcfg}
git show ${target_ref}:src/config.json  > ${newcfg}

# run invariant check on head commit version vs staged version
node src/validate-new-config.js "${oldcfg}" "${newcfg}"

## check for invalid line-endings
grep -q $'\r' "${newcfg}" \
  && echo "invalid line-endings in ${newcfg}" \
  && exit 1

exit 0
