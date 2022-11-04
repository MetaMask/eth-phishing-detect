#!/usr/bin/env bash

# process_list adds new hosts from ADD_HOSTS_HERE subdirectory to list
process_list() {
  _list=$1
  git show ADD_HOSTS_HERE/$_list | grep . >/dev/null \
    && node src/add-hosts.js $_list \
      $(git show --name-only --oneline ADD_HOSTS_HERE/$_list/ | tail -n +2 | xargs -r grep -hEv '^$|^#') \
    && echo "done $_list" || echo "skipped $_list"
}

process_list allowlist
process_list blocklist
process_list fuzzylist

# name of new branch
export _branch=ci-merge-$(git rev-parse --short HEAD)

# create commit with list changes and push
#git diff src/config.json \
#    && git checkout -b develop --track origin/develop #\
#    && git add src/config.json \
#    && git rm ADD_HOSTS_HERE/*/* \
#    && git commit -m 'update hostlists' \
#    && git push -u origin $_branch

echo 'done'
