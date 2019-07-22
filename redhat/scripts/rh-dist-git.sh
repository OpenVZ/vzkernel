#!/bin/bash

# clones and updates a dist-git repo
# $1: branch to be used
# $2: local pristine clone of dist-git
# $3: alternate tmp directory (if you have faster storage)
# $4: alternate dist-git server
# $5: kernel source tarball
# $6: kabi whitelists tarball
# $7: dwarf-bases kabi tarball
# $8: zstream build
# $9: package name

rhdistgit_branch=$1;
rhdistgit_cache=$2;
rhdistgit_tmp=$3;
rhdistgit_server=$4;
rhdistgit_tarball=$5;
rhdistgit_kabi_tarball=$6;
rhdistgit_kabidw_tarball=$7;
rhdistgit_zstream_flag=$8;
package_name=$9;
rhel_major=${10};
rhpkg_bin=${11};

redhat=$(dirname $0)/..;
topdir=$redhat/..;

function die
{
	echo "Error: $1" >&2;
	exit 1;
}

function upload()
{
	[ -n "$RH_DIST_GIT_TEST" ] && return
	$rhpkg_bin upload "$@" >/dev/null || die "uploading $@";
}

if [ -z "$rhdistgit_branch" ]; then
	echo "$0 <branch> [local clone] [alternate tmp] [alternate dist-git server]" >&2;
	exit 1;
fi

echo "Cloning the repository"
# clone the dist-git, considering cache
tmpdir=$($redhat/scripts/clone_tree.sh "$rhdistgit_server" "$rhdistgit_cache" "$rhdistgit_tmp" "$package_name" "$rhel_major" "$rhpkg_bin");

echo "Switching the branch"
# change in the correct branch
cd $tmpdir/$package_name;
$rhpkg_bin switch-branch $rhdistgit_branch || die "switching to branch $rhdistgit_branch";

echo "Copying updated files"
# copy the required files (redhat/git/files)
$redhat/scripts/copy_files.sh "$topdir" "$tmpdir" "$package_name";

echo "Uploading new tarballs"
# upload tarballs
sed -i "/linux-.*.tar.xz/d" $tmpdir/$package_name/{sources,.gitignore};
upload_list="$rhdistgit_tarball"

# Only upload kernel-abi-whitelists tarball if its release counter changed.
if [ "$rhdistgit_zstream_flag" == "no" ]; then
	if ! grep -q "$rhdistgit_kabi_tarball" $tmpdir/$package_name/sources; then
		sed -i "/kernel-abi-whitelists.*.tar.bz2/d" $tmpdir/$package_name/{sources,.gitignore};
		upload_list="$upload_list $rhdistgit_kabi_tarball"
	fi
	if ! grep -q "$rhdistgit_kabidw_tarball" $tmpdir/$package_name/sources; then
		sed -i "/kernel-kabi-dw-.*.tar.bz2/d" $tmpdir/$package_name/{sources,.gitignore};
		upload_list="$upload_list $rhdistgit_kabidw_tarball"
	fi
fi

upload $upload_list

echo "Creating diff for review ($tmpdir/diff) and changelog"
# diff the result (redhat/cvs/dontdiff). note: diff reuturns 1 if
# differences were found
diff -X $redhat/git/dontdiff -upr $tmpdir/$package_name $redhat/rpm/SOURCES/ > $tmpdir/diff;
# creating the changelog file
$redhat/scripts/create_distgit_changelog.sh $redhat/rpm/SOURCES/$package_name.spec \
	"$rhdistgit_zstream_flag" "$package_name" >$tmpdir/changelog

# all done
echo "$tmpdir"
