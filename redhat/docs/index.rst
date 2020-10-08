.. Fedora Kernel and ARK Documentation documentation master file, created by
   sphinx-quickstart on Thu May  7 14:44:56 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

=================
Fedora/ARK Kernel
=================

This documentation covers setting up a development environment, the repository
layout, and the general contribution workflow.

.. _quick-start:

Quick Start
===========

Setup
-----

To start with you need to:

1. Make a `GitLab account`_ if you do not already have one.
2. `Fork the ARK tree`_. Wait patiently for this to complete.
3. Setup `Koji`_ and `Mock`_ if necessary.

Once GitLab finishes forking the repository (this can take a while):

::

   # Cloning with these URLs requires that you have an SSH key registered with GitLab
   # If you've not yet set up keys, you can clone with with:
   # git clone https://gitlab.com/<your gitlab name>/kernel-ark.git && cd kernel-ark
   # git remote add -f upstream https://gitlab.com/cki-project/kernel-ark.git
   git clone git@gitlab.com:<your gitlab name>/kernel-ark.git && cd kernel-ark
   git remote add -f upstream git@gitlab.com:cki-project/kernel-ark.git

   # Install build dependencies
   sudo dnf install -y make gcc flex bison bzip2 rpm-build
   git checkout upstream/ark-latest
   # If you're on Fedora, you need to run:
   # ln -s /usr/bin/python3 /usr/libexec/platform-python
   make dist-srpm
   sudo dnf builddep -y redhat/rpm/SPECS/kernel.spec


Building an SRPM
----------------

The configuration and build scripts are in the ``os-build`` branch and
are regularly updated to work with Linus's master branch. To build an
SRPM, start by checking out the source tree you'd like to build. In this
example, we'll assume that is Linus's master branch, but it could just
as easily be Fedora's ``ark-patches`` branch (Linus's tree + Fedora
patches) , a sub-system maintainer's tree, or your own creation.

::

   git checkout linus/master
   git merge -m "Merge branch 'os-build'"  os-build
   # Fedora carries a patch to alter this setting, so we need to change the configuration to build a vanilla tree.
   # If you're targeting RHEL and have brew/rhpkg installed, use "make DIST=.elrdy dist-srpm" instead
   make dist-srpm

You can now build the SRPM however you like:

::

   # Build the SRPM locally
   mock redhat/rpm/SRPMS/kernel*src.rpm
   # Build the SRPM in Fedora's Koji
   koji build --scratch rawhide redhat/rpm/SRPMS/kernel*src.rpm

Want to add a patch? Just git-cherry-pick it or apply it with git-am and
re-run ``make dist-srpm``. Change configurations in ``redhat/configs/``
(consult the repository layout for details on this).


Contributor Guide
=================

.. toctree::
   :maxdepth: 2

   repository-layout
   submitting-contributions


Maintainer Guide
================

.. toctree::
   :maxdepth: 2

   maintaining


.. _GitLab account: https://gitlab.com/users/sign_in#register-pane
.. _Fork the ARK tree: https://gitlab.com/cki-project/kernel-ark/-/forks/new
.. _Koji: https://fedoraproject.org/wiki/Using_the_Koji_build_system#Koji_Setup
.. _Mock: https://fedoraproject.org/wiki/Using_Mock_to_test_package_builds#How_do_I_set_up_Mock.3F


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
