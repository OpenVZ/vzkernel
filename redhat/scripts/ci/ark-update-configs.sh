#!/bin/bash
#
# This script is intended to regularly update the os-build branch with the latest
# configuration options from upstream. It merges the given reference into
# os-build, adds all new configuration symbols to the pending/ config directory,
# and creates a branch for each new config group.
#
# If the upstream branch fails to merge and the REPORT_BUGS environment variable
# is set, an issue is filed against the provided project ID.
#
# Arguments:
#   1) The git object to merge into os-build. This should be something from
#	Linus's master branch, usually either a tag such as v5.5-rc3 or just
#	linus/master. The default is "master".
#   2) The Gitlab project ID to file issues against. See the project page on
#	Gitlab for the ID. For example, https://gitlab.com/cki-project/kernel-ark/
#	is project ID 13604247. The default is "13604247".

set -e

UPSTREAM_REF=${1:-master}
PROJECT_ID=${2:-13604247}

ISSUE_DESCRIPTION="A merge conflict has occurred and must be resolved manually.

To resolve this, do the following:

1. git checkout os-build
2. git merge master
3. Use your soft, squishy brain to resolve the conflict as you see fit.
4. git push
"

git checkout os-build
if ! git merge -m "Merge '$UPSTREAM_REF' into 'os-build'" "$UPSTREAM_REF"; then
	git merge --abort
	printf "Merge conflict; halting!\n"
	if [ -n "$REPORT_BUGS" ]; then
		ISSUES=$(gitlab project-issue list --state "opened" --labels "Configuration Update" --project-id "$PROJECT_ID")
		if [ -z "$ISSUES" ]; then
			gitlab project-issue create --project-id "$PROJECT_ID" \
				--title "Merge conflict between '$UPSTREAM_REF' and 'os-build'" \
				--labels "Configuration Update" \
				--description "$ISSUE_DESCRIPTION"
		fi
	fi
	exit 1
fi

make FLAVOR=fedora dist-configs-commit
make FLAVOR=rhel dist-configs-commit

if git show -s --oneline HEAD | grep -q "AUTOMATIC: New configs"; then
	./redhat/gen_config_patches.sh
else
	printf "No new configuration values exposed from merging %s into os-build\n" "$UPSTREAM_REF"
fi
