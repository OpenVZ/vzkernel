#!/bin/bash

GIT_DEPTH=$1

set -x

git fetch --depth=$GIT_DEPTH origin
git checkout -b new_clog_$RANDOM origin/internal
git checkout origin/master -- redhat/kernel.changelog-8.99
git add redhat/kernel.changelog-8.99
git checkout origin/master -- redhat/marker
git add redhat/marker
git config user.name "CKI@GitLab"
git config user.email "cki-project@redhat.com"

# Did anything change?
LINES_CHANGED=$(git diff --cached | wc -l)
if [ "${LINES_CHANGED}" != "0" ]; then
    git commit -m "Updated changelog"
    git remote add gitlab git@gitlab.com:cki-project/kernel-ark.git
    ssh-keyscan -H gitlab.com >> ~/.ssh/known_hosts
    git push -o merge_request.create \
                -o merge_request.target=internal \
                -o merge_request.title="Changelog Update" \
                -o merge_request.remove_source_branch \
                -o merge_request.label="Do Not Email" \
                gitlab
fi
