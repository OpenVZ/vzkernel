#!/bin/bash
#
# Generate a release tag and, if based on a tagged upstream release, a set
# of release branches. This script will rebase the ark-patches branch, update
# internal with the latest configurations, and apply any merge requests labeled
# with "Include in Releases".

set -e

UPSTREAM_REF=${1-master}
PROJECT_ID=${2:-13604247}

# Detect if there's one or more prior releases for this upstream ref.
if git describe "$UPSTREAM_REF" | grep -q -c '\-g'; then
	SHORT_COMMIT=$(git describe "$UPSTREAM_REF" | cut -d "g" -f 2)
	BASE_RELEASE=$(git tag -l | grep "$SHORT_COMMIT" | tail -n 1)
else
	if git describe "$UPSTREAM_REF" | grep -q -c "\-"; then
		RC_LEVEL="0.$(git describe "$UPSTREAM_REF" | cut -d "-" -f 2)"
		VERSION=$(git describe "$UPSTREAM_REF" | cut -d "-" -f 1 | cut -c 2-)
	else
		RC_LEVEL=""
		VERSION=$(git describe "$UPSTREAM_REF" | cut -c 2-)
	fi
	BASE_RELEASE=$(git tag -l | grep -E "kernel-$VERSION\.0-$RC_LEVEL\.[0-9]+" | tail -n 1)
fi
if [ -n "$BASE_RELEASE" ]; then
	printf "There's already a release for %s (tagged as %s); if you're trying \
		to create a new release check out that tag, apply any commits you \
		want, and then run \"touch localversion && make rh-release && make \
		rh-release-tag\".\n" "$UPSTREAM_REF" "$BASE_RELEASE"
	exit 3
fi

git checkout internal
./redhat/scripts/ci/ark-rebase-patches.sh "$UPSTREAM_REF" "$PROJECT_ID"
git checkout internal
./redhat/scripts/ci/ark-update-configs.sh "$UPSTREAM_REF" "$PROJECT_ID"

if git tag -v "$UPSTREAM_REF" > /dev/null 2>&1; then
	git checkout -b ark/"$UPSTREAM_REF" ark/patches/"$UPSTREAM_REF"
	RELEASE_BRANCHES=" ark/$UPSTREAM_REF ark/patches/$UPSTREAM_REF"
else
	# This is a snapshot release so we're only going to make a tag
	git checkout --detach ark-patches && git describe
	RELEASE_BRANCHES=""
fi
git merge -m "Merge configuration and build scripts" internal

MR_PATCHES=$(gitlab project-merge-request list --project-id=13604247 \
	--labels="Include in Releases" --state=opened | grep -v "^$" | sort | \
	awk '{ print "https://gitlab.com/cki-project/kernel-ark/-/merge_requests/" $2 ".patch" }')
for patch_url in $MR_PATCHES; do
	curl -sL "$patch_url" | git am
done

touch localversion
make rh-release
make rh-release-tag
RELEASE=$(git describe)
git checkout ark-latest
git reset --hard "$RELEASE"

printf "All done!

To push all the release artifacts, run:

git push internal
for branch in \$(git branch | grep configs/\"\$(date +%%F)\"); do
\tgit push -o merge_request.create -o merge_request.target=internal \
 -o merge_request.remove_source_branch upstream \"\$branch\"
done
git push upstream %s%s
git push -f upstream ark-latest\n" "$RELEASE" "$RELEASE_BRANCHES"
