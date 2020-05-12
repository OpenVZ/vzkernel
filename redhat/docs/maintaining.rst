===========
Maintenance
===========

This guide covers common maintenance tasks and is primarily aimed at
kernel maintainers. It assumes you have write access to
`https://gitlab.com/cki-project/kernel-ark.git <https://gitlab.com/cki-project/kernel-ark.git>`__
and the remote in your clone is called "upstream", as set up in the
quick start guide.

The repository is used for both the Fedora kernel and the RHEL Always
Ready kernel (ARK). Thus, it contains two sets of configurations.

Every release requires the maintainer to:

1. Rebase the downstream kernel patches
2. Update the configuration
3. Create a release branch and/or tag

Once that is done, the result can be imported into a dist-git repository
and built in Koji.

There is a script to automate the entire process which is run nightly by
CI/CD. You can run it locally:

::

   # Ensure we've got a clean check out for all the branches we're about to use
   git checkout master && git pull
   git checkout ark-patches && git reset --hard upstream/ark-patches
   git checkout internal && git pull

   # Create a release based on "master", which tracks mainline
   ./redhat/scripts/ci/ark-create-release.sh master

The individual steps taken are described below for the curious.

Rebasing Kernel Patches
-----------------------

The downstream kernel patches are in a branch called ``ark-patches``.
This branch is regularly rebased onto Linus's master branch.

The rebase consists of the following steps:

1. Ensure your checkout is in a clean state:

::

   git checkout master
   git reset --hard upstream/master
   git checkout ark-patches
   git reset --hard upstream/ark-patches
   git checkout os-build
   git reset --hard upstream/os-build

2. Rebase the kernel patches onto master:
   ``./redhat/scripts/ci/ark-rebase-patches.sh "master"``. If you'd like
   for the script to drop patches that conflict and file issues on the
   GitLab issue tracker, ensure the "REPORT_BUGS" environment variable
   is set to something other than an empty string.

3. If rebasing onto a tag, the script will create a branch for this
   revision of the kernel patches. This is useful when comparing the
   state of the patches between versions. Push this to the remote
   repository with ``git push upstream ark/patches/<tag>``.

4. If the patches required conflict resolution, update the remote with
   ``git push -f upstream ark-patches``. If they didn't, there's no need
   to update the branch as force pushing it breaks existing merge
   requests against it.

Common Problems
~~~~~~~~~~~~~~~

There are a few issues that can occur during the patch rebase.

Patch Cannot Be Applied
^^^^^^^^^^^^^^^^^^^^^^^

Patches regularly fail to apply because upstream changed some code being
patched. When this occurs, if the fix is trivial, you can simply fix up
the patch during the ``git-rebase``. Otherwise, file an issue to fix the
patch and skip it during the rebase.

Once a dropped patch has a fix, submit a merge request to
``ark-patches`` with the fixed-up patch. If you aren't confident you can
fix it yourself, try contacting the original author and ask them to fix
their patch.

Patch Applies But Is Broken
^^^^^^^^^^^^^^^^^^^^^^^^^^^

This problem occurs less frequently, but is also less straightforward to
detect and fix. A patch might cleanly apply, but an interface it uses
has changed in some way (e.g. a function got renamed). Ideally the
change causes the build to fail.

Assuming you know how to fix the problem, use the following approach:

1. Start a branch based of the latest ``ark-patches`` branch and fix the
   problem as you see fit.
2. Commit the change, including a
   ``Fixes: <short sha of commit in ark-patches it fixes>`` tag in the
   commit, along with references to the upstream commit that introduced
   the breaking change and any other details you see fit. If you
   reference a commit that is not upstream (that is, any patch in
   ark-patches) be sure to add a [x] reference and link to the commit so
   email users can see the commit in question easily during review.
3. Submit a merge request against ``ark-patches``
4. Once reviewed, merge the merge request. When rebasing
   ``ark-patches``, squash the fix into the commit it fixes so that the
   patches in ``ark-patches`` continue to be self-contained.

An example of this is
`https://gitlab.com/cki-project/kernel-ark/merge_requests/90 <https://gitlab.com/cki-project/kernel-ark/merge_requests/90>`__.

Configuration
-------------

Once the patches are rebased, update the configuration branch:

1. Set defaults for any new configuration files:

::

   git checkout os-build
   ./redhat/scripts/ci/ark-update-configs.sh "master"

2. Open a merge request for each branch created in step 1 (if any):

::

   git checkout os-build
   if git branch | grep configs/"$(date +%F)"; then
       git push upstream os-build
       for branch in $(git branch | grep configs/"$(date +%F)"); do
           git push -o merge_request.create -o merge_request.target=os-build -o merge_request.remove_source_branch upstream "$branch"
       done
   fi

Release branch
--------------

Once the kernel patches and configuration have been updated for the new
release, it's time to create the release branch and/or tag. If this is a
snapshot build (i.e. master does not point to a tag), we only create a
tag.

Snapshot Release
~~~~~~~~~~~~~~~~

::

   git checkout -b build-branch ark-patches
   git merge -m "Merge configuration and build scripts" os-build
   # If there's a temporary fix you want in just this build, you can run git-cherry-pick here.
   touch localversion
   make dist-release
   make dist-release-tag
   git push upstream $(git describe)
   git branch -D build-branch

Upstream Release
~~~~~~~~~~~~~~~~

::

   UPSTREAM_REF=<tag>
   git checkout -b ark/"$UPSTREAM_REF" ark/patches/"$UPSTREAM_REF"
   git merge -m "Merge configuration and build scripts" os-build
   touch localversion
   make dist-release
   make dist-release-tag
   git push $(git describe) ark/"$UPSTREAM_REF" ark/patches/"$UPSTREAM_REF"
   git checkout ark-latest && git reset --hard ark/"$UPSTREAM_REF" && git push -f upstream ark-latest

Building
--------

After a release branch has been prepared, it's time to build it. This
guide assumes you have Koji and/or Brew installed and properly
configured. It also assumes you've authenticated and have permissions to
build.

Fedora
~~~~~~

This requires having fedpkg installed.

From the release branch/tag, run:

::

   # Checks out the Fedora dist-git repository and copies everything from the source tree into it
   #
   # By default, this creates a directory in /tmp, but the location can be set with RHDISTGIT_TMP.
   # If you already have a local clone of the Fedora dist-git repository, it can be used with RHDISTGIT_CACHE=<path-to-repo>.
   #
   # localversion sets the buildid, releases should have an empty build id
   rm localversion
   touch localversion
   make dist-dist-git

   cd /tmp/RHEL*/kernel
   git commit -a -s -F ../changelog
   fedpkg push
   fedpkg build

ARK
~~~

This requires having rhpkg-sha512 installed and brew.

From the release branch/tag, run:

::

   # localversion sets the buildid, releases should have an empty build id
   rm localversion
   touch localversion
   make DIST=.elrdy dist-dist-git
   cd /tmp/RHEL-8*/kernel
   git commit -a -s -F ../changelog
   git push
   rhpkg tag -F ../changelog
   git push origin $(git describe)
   rhpkg build --target temp-ark-rhel-8-test --skip-nvr-check

