#!/usr/bin/env bash

# USAGE: compare-git-configs.sh [base_ref:HEAD] [target_ref]

set -e

base_ref="${1:-$(git show-ref --head -s HEAD | head -c7)}"
target_ref=$2


if ! git diff --staged --quiet --exit-code --merge-base $base_ref $target_ref src/config.json; then
  PATH=$(pwd)/node_modules/.bin:$PATH

  oldcfg=$(pwd)/src/.config-${base_ref}.json
  newcfg=$(pwd)/src/.config-${base_ref}-$(date -u '+%s')-dirty.json
  git show ${base_ref}:src/config.json    > ${oldcfg}
  git show ${target_ref}:src/config.json  > ${newcfg}

  # run invariant check on head commit version vs staged version
  node src/validate-new-config.js "${oldcfg}" "${newcfg}"

  ## check for invalid line-endings
  grep -q $'\r' "${newcfg}" \
    && echo "invalid line-endings in ${newcfg}" \
    && exit 1
fi

exit 0
