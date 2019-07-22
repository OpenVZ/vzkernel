#!/bin/bash

# Copy required files to dist-git. Uses redhat/git/files to know which files
# to copy
#
# $1: git source tree directory
# $2: cloned tree
# $3: package name

tree="$1";
cloned="$2";
package_name="$3";
redhat="$1/redhat";
sources="$redhat/rpm/SOURCES";
spec="$sources/$package_name.spec";

function die
{
	echo "Error: $1" >&2;
	exit 1;
}

if [ -z "$tree" -o ! -d "$sources" ]; then
	die "\"$tree\" doesn't seem to be a valid $package_name source tree";
fi

if [ ! -d "$cloned" ]; then
	die "\"$cloned\" doesn't seem to be a valid directory";
fi

cd $cloned/$package_name || die "\"$cloned\" doesn't seem to have a dist-git clone";

# copy the other files
cp $(cat $redhat/git/files | sed -e "s,^,$sources/,") . || die "Unable to copy files";
git add $(cat $redhat/git/files);

# copy the split out patches. We can't put this with the rest of the files
# because the version changes
cp $sources/patch-*-redhat.patch .
git add patch-*-redhat.patch

exit 0;
