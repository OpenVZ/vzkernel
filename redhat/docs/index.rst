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

   # Setup mirroring of kernel-ark to your fork.  This helps keep your
   # fork in sync with the kernel-ark project and avoids setting up a second
   # remote tree to manage.
   #
   # Goto: https://gitlab.com/<your gitlab name>/kernel-ark/-/settings/repository
   # Click on 'Mirroring repositories'
   # Enter in Git Repository URL: https://gitlab.com/cki-project/kernel-ark.git
   # Ensure 'Mirror direction' is 'Pull'
   # Password is blank and checkboxes can be left blank (your choice)
   # Click 'Mirror Repository'  (will take 20 minutes to establish)
   #
   # Cloning with these URLs requires that you have an SSH key registered with GitLab
   # If you've not yet set up keys, you can clone with with:
   # git clone https://gitlab.com/<your gitlab name>/kernel-ark.git && cd kernel-ark
   git clone git@gitlab.com:<your gitlab name>/kernel-ark.git && cd kernel-ark

   # Install build dependencies
   sudo dnf install -y make gcc flex bison bzip2 rpm-build
   # If you're on Fedora, you need to run:
   # ln -s /usr/bin/python3 /usr/libexec/platform-python
   make dist-srpm
   sudo dnf builddep -y redhat/rpm/SPECS/kernel.spec


Building an SRPM
----------------

The configuration and build scripts are in the ``os-build`` branch and
are regularly updated to work with Linus's master branch.

::

   git checkout os-build
   git pull
   make dist-srpm

You can now build the SRPM however you like:

::

   # Build the SRPM locally
   mock redhat/rpm/SRPMS/kernel*src.rpm
   # Build the SRPM in Fedora's Koji
   koji build --scratch rawhide redhat/rpm/SRPMS/kernel*src.rpm
   koji build --scratch eln redhat/rpm/SRPMS/kernel*src.rpm

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
