include Makefile.common
include Makefile.rhpkg

LANG=C

ifeq ("$(ZSTREAM)", "yes")
  __YSTREAM = no
  ifeq ("$(origin RHDISTGIT_BRANCH)", "command line")
    __ZSTREAM = branch
  else
    __ZSTREAM = yes
  endif
  BUILDOPTS += +kabidupchk
else
  __ZSTREAM = no
  ifeq ("$(EARLY_YSTREAM)", "yes")
    __YSTREAM = early
  else
    __YSTREAM = yes
  endif
endif


ifeq ("$(IS_FEDORA)", "1")
   DIST_TARGET=fedora
else
   DIST_TARGET=rhel
endif

ifeq ("$(NO_CONFIGCHECKS)","1")
   PROCESS_CONFIGS_OPTS=
   PROCESS_CONFIGS_CHECK_OPTS=
   BUILDOPTS += -configchecks
else
   PROCESS_CONFIGS_CHECK_OPTS=-n -t -c
   PROCESS_CONFIGS_OPTS=-n -w -c
endif

BUILD_TARGET ?= --scratch $(BUILD_SCRATCH_TARGET)

RHGITURL?=$(shell git config rhg.url || git config remote.origin.url)
RHGITCOMMIT?=$(shell git log -1 --pretty=format:%H)

# this section is needed in order to make O= to work
_OUTPUT := ..
ifeq ("$(origin O)", "command line")
  _OUTPUT := $(O)
  _EXTRA_ARGS := O=$(_OUTPUT)
endif

CURARCH := $(shell uname -m)
ARCHCONFIG := $(shell uname -m | sed -e s/x86_64/X86_64/ \
				     -e s/s390x/S390/ -e s/ppc.*/PPC/ )

KABIDW := $(REDHAT)/kabi-dwarf

include Makefile.cross

default: rh-help

rh-python-check:
	@if [ ! -f /usr/libexec/platform-python ]; then \
		if ! which python3 > /dev/null 2>&1; then \
			echo "ERROR: Python 3 is needed." ; \
			exit 1; \
		fi; \
		echo "ERROR: your build environment is not compatible with RHEL8."; \
		echo "To fix this, run:"; \
		echo "ln -s `which python3` /usr/libexec/platform-python"; \
		exit 1; \
	fi

rh-kabi: rh-python-check
	@for KABIARCH in $(ARCH_LIST); do \
		$(REDHAT)/kabi/show-kabi -k $(REDHAT)/kabi/kabi-module/ -m \
			-a $$KABIARCH -r $(RHEL_MAJOR).$(RHEL_MINOR) > $(REDHAT)/kabi/Module.kabi_$$KABIARCH;\
		for i in {0..$(RHEL_MINOR)}; do \
			mkdir -p $(REDHAT)/kabi/kabi-rhel$(RHEL_MAJOR)$$i/;\
			$(REDHAT)/kabi/show-kabi -k $(REDHAT)/kabi/kabi-module/ -s -a $$KABIARCH \
			-r $(RHEL_MAJOR).$$i > $(REDHAT)/kabi/kabi-rhel$(RHEL_MAJOR)$$i/kabi_whitelist_$$KABIARCH;\
		done;\
	done;
	@(cd $(REDHAT)/kabi/ && ln -Tsf kabi-rhel$(RHEL_MAJOR)$(RHEL_MINOR) kabi-current)

rh-kabi-dup: rh-python-check
	@for KABIARCH in $(ARCH_LIST); do \
		touch $(REDHAT)/kabi/Module.kabi_dup_$$KABIARCH;\
		if [ -d $(REDHAT)/kabi/kabi-dup-module/kabi_$$KABIARCH ]; then \
			$(REDHAT)/kabi/show-kabi -k $(REDHAT)/kabi/kabi-dup-module/ -m \
				-a $$KABIARCH -r $(RHEL_MAJOR).$(RHEL_MINOR) > \
				$(REDHAT)/kabi/Module.kabi_dup_$$KABIARCH;\
		fi \
	done;

rh-check-kabi: rh-kabi
	@if [ ! -e $(_OUTPUT)/Module.symvers ]; then \
		echo "ERROR: You must compile the kernel and modules first";\
		exit 1;\
	fi
	@$(REDHAT)/kabi/check-kabi -k $(REDHAT)/kabi/Module.kabi_$(MACH) \
	 -s $(_OUTPUT)/Module.symvers

rh-check-kabi-dup: rh-kabi-dup
	@if [ ! -e $(_OUTPUT)/Module.symvers ]; then \
		echo "ERROR: You must compile the kernel and modules first";\
		exit 1;\
	fi
	@$(REDHAT)/kabi/check-kabi -k $(REDHAT)/kabi/Module.kabi_dup_$(MACH) \
	-s $(_OUTPUT)/Module.symvers

rh-kabi-dw-base: rh-kabi
	@echo "Generating baseline dataset for KABI DWARF-based comparison..."
	@echo "**** GENERATING DWARF-based kABI baseline dataset ****"
	@$(KABIDW)/run_kabi-dw.sh generate \
		$(REDHAT)/kabi/kabi-current/kabi_whitelist_$(CURARCH) \
		$(_OUTPUT) $(KABIDW)/base/$(CURARCH)/

rh-kabi-dw-check: rh-kabi
	@if [ ! -d $(KABIDW)/base/$(CURARCH) ]; then \
		echo "**** ERROR: ****"; \
		echo "Comparison base not found in $(KABIDW)/base/$(CURARCH)."; \
		echo "Please run \"make rh-kabi-dw-base\" first!"; \
		exit 1; \
	fi
	@echo "**** GENERATING DWARF-based kABI dataset ****"
	@$(KABIDW)/run_kabi-dw.sh generate \
		$(REDHAT)/kabi/kabi-current/kabi_whitelist_$(CURARCH) \
		$(_OUTPUT) $(KABIDW)/base/$(CURARCH).tmp/
	@echo "**** KABI DWARF-based comparison report ****"
	@$(KABIDW)/run_kabi-dw.sh compare \
		$(KABIDW)/base/$(CURARCH) $(KABIDW)/base/$(CURARCH).tmp || :
	@echo "**** End of KABI DWARF-based comparison report ****"
	@rm -rf $(KABIDW)/base/$(CURARCH).tmp

rh-configs: rh-configs-prep
	@cd $(REDHAT)/configs; VERSION=$(KVERSION) ./generate_all_configs.sh rhel 1; \
	./process_configs.sh $(PROCESS_CONFIGS_OPTS) $(PACKAGE_NAME) $(KVERSION)

rh-configs-check: rh-configs-prep
	cd $(REDHAT)/configs; ./process_configs.sh $(PROCESS_CONFIGS_CHECK_OPTS) $(PACKAGE_NAME)

rh-configs-prep: rh-clean-configs
	cd $(REDHAT)/configs; TARGET=$(DIST_TARGET) ./build_configs.sh $(PACKAGE_NAME) $(ARCH_MACH)

rh-configs-arch: ARCH_MACH = $(MACH)
rh-configs-arch: rh-configs

rh-clean-configs:
	cd $(REDHAT)/configs; rm -f kernel-*.config

rh-clean-sources:
	@rm -f $(RPM)/SPECS/*
	@for i in $(SOURCES)/*; do \
		rm -f $$i; \
	done;

rh-clean-rpmdirs:
	@for i in $(RPM)/{BUILD,SRPMS,RPMS,SPECS}/*; do \
		rm -rf $$i; \
	done;

rh-clean: rh-clean-sources rh-clean-configs rh-clean-rpmdirs

rh-stub-key:
	@echo "Copying pre-generated keys";
	@echo "*** THIS IS NOT RECOMMENDED ***";
	@echo "To be safe, keys should be created once for every build";
	@echo "Use this option only for development builds";
	@cp keys/stub_key.x509 $(_OUTPUT)/;
	@cp keys/stub_key.priv $(_OUTPUT)/;

# force tarball to be regenerated if HEAD changes
.PHONY:	$(TARBALL)
$(TARBALL):
	@if [ $(SINGLE_TARBALL) -eq 1 ]; then \
		scripts/create-tarball.sh $(GITID) $(TARBALL) linux-$(KVERSION)-$(PKGRELEASE); \
	else \
		scripts/create-tarball.sh $(MARKER) $(TARBALL) linux-$(TARFILE_RELEASE); \
	fi

.PHONY: $(KABI_TARBALL)
$(KABI_TARBALL):
	@(cd kabi && tar cjvf $(SOURCES)/$(KABI_TARFILE) kabi-rhel$(RHEL_MAJOR)* kabi-current)

.PHONY: $(KABIDW_TARBALL)
$(KABIDW_TARBALL):
	@if [ ! -d $(KABIDW)/base ]; then \
		mkdir -p $(KABIDW)/base; \
	fi
	@(cd kabi-dwarf && tar cjvf $(SOURCES)/$(KABIDW_TARFILE) base run_kabi-dw.sh)


rh-git-version-check:
	@# genspec.sh uses pathspec magic that wasn't introduced until version 2.13
	@IFS=" ."; \
	set -- $$(git --version); \
	IFS=; \
	if [ "$$3" -lt 2 -o \( "$$3" -eq 2 -a "$$4" -lt 13 \) ]; then \
		echo "ERROR: You need git version 2.13 or newer to run some setup commands"; \
		exit 1; \
	fi

setup-source: rh-git-version-check rh-clean-sources
	@cp $(REDHAT)/$(SPECFILE).template $(SOURCES)/$(SPECFILE)
	@if [ ! -e  $(REDHAT)/$(CHANGELOG) ]; then \
		echo "Creating $(CHANGELOG) as copy of $(CHANGELOG_PREV)"; \
		cp $(REDHAT)/$(CHANGELOG_PREV) $(REDHAT)/$(CHANGELOG); \
	fi
	@cp $(REDHAT)/$(CHANGELOG) $(SOURCES)/$(CHANGELOG)
	@$(REDHAT)/genspec.sh $(SOURCES) $(SOURCES)/$(SPECFILE) $(SOURCES)/$(CHANGELOG) $(PKGRELEASE) $(RPMKVERSION) $(RPMKPATCHLEVEL) $(RPMKSUBLEVEL) $(DISTRO_BUILD) $(RELEASED_KERNEL) $(SPECRELEASE) $(__ZSTREAM) "$(BUILDOPTS)" $(MARKER) `cat $(REDHAT)/marker` $(SINGLE_TARBALL) $(TARFILE_RELEASE)
	@cp $(SOURCES)/$(SPECFILE) $(SOURCES)/../SPECS/

sources-rh: $(TARBALL)
	@cp -l $(TARBALL) $(SOURCES)/ || cp $(TARBALL) $(SOURCES)/
	@touch $(TESTPATCH)
	@git diff --no-renames HEAD > $(TESTPATCH).tmp
	@# 1) filterdiff will return crap from the patches it just filtered,
	@#    that's why egrep is needed so if there're changes under redhat/
	@#    but not everywhere else, it will be empty just like
	@#    linux-kernel-test.patch
	@# 2) egrep -v will return "1" if it sucessfully removed index and diff
	@#    lines, which will be considered an error
	@($(FILTERDIFF) $(TESTPATCH).tmp | egrep -v "^index|^diff" >$(TESTPATCH).tmp2; true)
	@mv $(TESTPATCH).tmp2 $(TESTPATCH).tmp
	@diff $(TESTPATCH).tmp $(TESTPATCH) > /dev/null || \
		echo "WARNING: There are uncommitted changes in your tree or the changes are not in sync with linux-kernel-test.patch.  Either commit the changes or run 'make rh-test-patch'"
	@rm $(TESTPATCH).tmp
	@cp $(TESTPATCH) $(SOURCES)/linux-kernel-test.patch
	@cp fedora_files/* $(SOURCES);
	@cp rhel_files/* $(SOURCES);
	@cp cpupower.* \
		keys/rhel*.x509 \
		kabi/check-kabi \
		configs/$(PACKAGE_NAME)-*.config \
		keys/*.cer \
		update_scripts.sh \
		mod-extra.* \
		mod-extra-blacklist.sh \
		mod-internal.list \
		mod-sign.sh \
		configs/flavors \
		configs/generate_all_configs.sh \
		configs/process_configs.sh \
		parallel_xz.sh \
		generate_bls_conf.sh \
		$(SOURCES)/
	@for KABIARCH in $(ARCH_LIST); do \
		cp kabi/Module.kabi_$$KABIARCH $(SOURCES)/; \
		cp kabi/Module.kabi_dup_$$KABIARCH $(SOURCES)/; \
	done
	@(cd kabi && tar cjvf $(SOURCES)/$(KABI_TARFILE) kabi-rhel$(RHEL_MAJOR)* kabi-current)
	@if [ ! -d $(KABIDW)/base ]; then \
		mkdir -p $(KABIDW)/base; \
	fi
	@(cd kabi-dwarf && tar cjvf $(SOURCES)/$(KABIDW_TARFILE) base run_kabi-dw.sh)

rh-sources: setup-source rh-configs-check rh-kabi rh-kabi-dup sources-rh

rh-test-patch:
	@git diff --no-renames HEAD > $(TESTPATCH);
	@($(FILTERDIFF) $(TESTPATCH) | egrep -v "^index|^diff" >$(TESTPATCH).tmp; true)
	@mv $(TESTPATCH).tmp $(TESTPATCH);

rh-all-rpms: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) -ba $(RPM)/SOURCES/$(PACKAGE_NAME).spec

rh-srpm: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --nodeps -bs $(RPM)/SOURCES/$(PACKAGE_NAME).spec

rh-srpm-gcov:
	make rh-sources BUILDID=".gcov" BUILDOPTS="+gcov"
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --nodeps -bs $(RPM)/SOURCES/$(PACKAGE_NAME).spec

rh-rpms: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) --target noarch -bb $(RPM)/SOURCES/$(PACKAGE_NAME).spec

rh-kernel-%: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) --with $* --without vdso_install --without perf --without tools -bb $(RPM)/SOURCES/$(PACKAGE_NAME).spec

rh-prep: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --nodeps --target noarch -bp $(RPM)/SOURCES/$(PACKAGE_NAME).spec

rh-perf: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --without up --without smp --without zfcpdump --without debug --without doc --without headers --without  --without doc --without debuginfo --target $(MACH) -bb $(RPM)/SOURCES/$(PACKAGE_NAME).spec

rh-rpm-baseonly: rh-sources
	$(RPMBUILD) --define "_sourcedir $(SOURCES)" --define "_builddir $(RPM)/BUILD" --define "_srcrpmdir $(RPM)/SRPMS" --define "_rpmdir $(RPM)/RPMS" --define "_specdir $(RPM)/SPECS" --define "dist $(DIST)" --target $(MACH) --without debug --without debuginfo --without vdso_install --without bpftool --without perf --without tools -bb $(RPM)/SOURCES/$(PACKAGE_NAME).spec


# unless you know what you're doing, you don't want to use the next three ones
rh-release-finish: setup-source
	@cp $(SOURCES)/$(CHANGELOG) $(REDHAT)/$(CHANGELOG)
	@git add $(REDHAT)/$(CHANGELOG)
	@echo $(MARKER) > $(REDHAT)/marker
	@git add $(REDHAT)/marker
	@git commit -s ../Makefile.rhelver $(REDHAT)/marker $(REDHAT)/$(CHANGELOG) $(PACKAGE_NAME).spec.template -m "[redhat] $(PACKAGE_NAME)-$(STAMP_VERSION)-$(PREBUILD)$(BUILD)$(DIST)$(BUILDID)"
	@$(MAKE) rh-configs
	@$(MAKE) rh-kabi
	@$(MAKE) rh-kabi-dup
	@$(MAKE) sources-rh
rh-release: rh-clean-sources
	@$(REDHAT)/scripts/new_release.sh $(REDHAT) $(__YSTREAM) $(__ZSTREAM)
	@$(MAKE) rh-release-finish
rh-release-tag:
	@git tag -a -m "$(PACKAGE_NAME)-$(STAMP_VERSION)-$(PKGRELEASE)" $(PACKAGE_NAME)-$(STAMP_VERSION)-$(PKGRELEASE)

.PHONY: rh-brew rh-koji
rh-brew : BUILD_FLAGS ?= $(BREW_FLAGS) $(TEST_FLAGS)
rh-koji : BUILD_FLAGS ?= $(KOJI_FLAGS) $(TEST_FLAGS)
rhg-brew: BUILD_FLAGS ?= $(BREW_FLAGS) $(TEST_FLAGS)
rhg-koji: BUILD_FLAGS ?= $(KOJI_FLAGS) $(TEST_FLAGS)

rh-brew rh-koji: rh-%: rh-srpm
	$* build $(BUILD_FLAGS) $(BUILD_TARGET) $(SRPMS)/$(PACKAGE_NAME)-$(KVERSION)-$(PKGRELEASE).src.rpm $(OUTPUT_FILE)

rhg-brew rhg-koji: rhg-%:
	$* build $(BUILD_FLAGS) $(BUILD_TARGET) "$(RHGITURL)?redhat/koji#$(RHGITCOMMIT)"

.PHONY: $(REDHAT)/rpm/SOURCES/$(PACKAGE_NAME).spec
$(REDHAT)/rpm/SOURCES/$(PACKAGE_NAME).spec:
	@echo "rh-sources"
	@$(MAKE) rh-sources

rh-dist-git-test: export RH_DIST_GIT_TEST="1"
rh-dist-git-test: rh-dist-git

rh-dist-git: rh-srpm $(TARBALL) $(KABI_TARBALL) $(KABIDW_TARBALL)
ifeq ("$(RHDISTGIT_BRANCH)", "")
 $(error RHDISTGIT_BRANCH unset)
endif
	$(REDHAT)/scripts/rh-dist-git.sh "$(RHDISTGIT_BRANCH)" "$(RHDISTGIT_CACHE)" "$(RHDISTGIT_TMP)" "$(RHDISTGIT)" "$(TARBALL)" "$(KABI_TARBALL)" "$(KABIDW_TARBALL)" "$(__ZSTREAM)" "$(PACKAGE_NAME)" "$(RHEL_MAJOR)" "$(RHPKG_BIN)" "$(SRPMS)/$(PACKAGE_NAME)-$(KVERSION)-$(PKGRELEASE).src.rpm"

rh-rtg: rh-release
	@$(MAKE) rh-release-tag
	@$(MAKE) rh-dist-git

# RH_LATEST returns the value of the latest "known good" kernel from brew.
# This should not be confused with the latest top-of-tree development tag.
rh-get-latest:
	$(eval RH_LATEST:=$(shell brew latest-pkg --quiet rhel-${RHEL_MAJOR}.${RHEL_MINOR}.0-candidate kernel | awk ' { print $$1 } '))
	@echo "The latest kernel package tag is ${RH_LATEST}."

rh-os-version:
	@echo "OSVERSION: $(RHEL_MAJOR).$(RHEL_MINOR)"

rh-help:
	@echo  'Cleaning targets:'
	@echo  '  rh-clean          - Clean redhat/configs/ and redhat/rpm/ directories.'
	@echo  ''
	@echo  'Building targets:'
	@echo  '  rh-srpm           - Create a source RPM.'
	@echo  '  rh-all-rpms       - Create a source RPM and build binary RPMs locally.'
	@echo  '  rh-brew           - Create a source RPM and call brew to build binary RPMs.'
	@echo  '  rhg-brew          - Build RPMs using a remote git repo. [Configuration needed.]'
	@echo  '  rh-cross-all-rpms - Build RPMs for all supported archs using a cross compiler.'
	@echo  ''
	@echo  'Configuration targets:'
	@echo  '  rh-configs        - Create RHEL config files in redhat/config/.'
	@echo  ''
	@echo  'For detailed description and full list of targets, run `make rh-full-help`.'
	@echo  ''

rh-full-help:
	@echo  'Cleaning targets:'
	@echo  '  rh-clean            - Do rh-clean-sources, rh-clean-configs, & rh-clean-rpmdirs.'
	@echo  '  rh-clean-sources    - Clean the redhat/rpm/SOURCES/ directory.'
	@echo  '  rh-clean-configs    - Clean the redhat/configs/ directory.'
	@echo  '  rh-clean-rpmdirs    - Clean the redhat/rpm/{BUILD,SRPMS,RPMS,SPECS}/ directories.'
	@echo  ''
	@echo  'Building targets:'
	@echo  ' All RPM/SRPM files will be put under the redhat/rpm/ directory.'
	@echo  ''
	@echo  '  rh-srpm       - Create a source RPM and put it into the redhat/rpm/SRPMS/ directory.'
	@echo  '                  See the rh-brew target for available options.'
	@echo  '  rh-srpm-gcov  - Create a source RPM with gcov enabled and put it into the'
	@echo  '                  redhat/rpm/SRPMS/ directory.'
	@echo  '  rh-brew       - Create a kernel SRPM and then call brew to build the created SRPM.'
	@echo  '                  Add BUILDOPTS="+<opt> -<opt> [...]" to enable/disable build options.'
	@echo  '                  Available <opt>s and their default values:' \
		$$(sed -n -e 's/^%define with_\([^ \t]*\).*\?_without_.*/+\1/p' \
		          -e 's/^%define with_\([^ \t]*\).*\?_with_.*/-\1/p' kernel.spec.template | \
		grep -v 'only$$') | fmt -90
	@echo  '  rh-koji       - Create a kernel SRPM and then call koji to build the created SRPM.'
	@echo  '                  See the rh-brew target for available options.'
	@echo  '  rhg-brew      - Pass HEAD of the current git branch to brew to build an RPM set.'
	@echo  '                  Do not forget to push to the remote repository first.'
	@echo  '                  Preceed make command by RHGITCOMMIT=<commitID> to specify commit ID'
	@echo  '                  to use.'
	@echo  '                  To set the remote repo, invoke: git config rhg.url git://<repo_path>'
	@echo  '  rhg-koji      - Pass HEAD of the current git branch to koji to build an RPM set.'
	@echo  '                  Do not forget to push to the remote repository first.'
	@echo  '                  See the rhg-brew target for options and configuration.'
	@echo  '  rh-rpms       - Create the binary RPMS for the kernel.'
	@echo  '                  See the rh-brew target for available options.'
	@echo  '  rh-rpm-baseonly  - Create the binary RPMS for the kernel and modules only (no'
	@echo  '                     userspace tools or debuginfo).'
	@echo  '  rh-kernel-<type> - Create  binary RPMS for a particular kernel type.'
	@echo  '                     Available <type>s:'\
		$$(sed -n 's/^%define with_\([^ ]*only\).*/\1/p' kernel.spec.template)

	@echo  '  rh-all-rpms   - Create the binary RPMS and the SRPM for the kernel.'
	@echo  '                  See the rh-brew target for available options.'
	@echo  '  rh-prep       - Setup the redhat/rpm/BUILD/ directory with the kernel source.'
	@echo  '                  See the rh-brew target for available options.'
	@echo  '  rh-test-patch - Create a diff against HEAD and put it in linux-kernel-test.patch.'
	@echo  '                  Then linux-kernel-test.patch will be added to the kernel build.'
	@echo  '  rh-stub-key   - Use pre generated keys to speed local test builds.'
	@echo  '  rh-cross-download     - [x86_64 only] download cross compiler rpms.'
	@echo  '  rh-cross-all-builds   - [x86_64 only] execute "rpmbuild -bc" for all supported'
	@echo  '                          archs using RHEL cross compiler.'
	@echo  '  rh-cross-<arch>-build - [x86_64 only] execute "rpmbuild -bc" for specified'
	@echo  '                          <arch> using RHEL cross compiler.'
	@echo  '                          Supported <arch>s: x86_64'\
		$$(sed -n 's/.*--target \([^ ]*\).*/\1/p' Makefile.cross | sort -u)
	@echo  '  rh-cross-all-rpms     - [x86_64 only] execute rpm builds for all supported'
	@echo  '                          archs using RHEL cross compiler.'
	@echo  '  rh-cross-<arch>-rpm   - [x86_64 only] execute rpm builds for specified'
	@echo  '                          <arch> using RHEL cross compiler.'
	@echo  '                          See rh-cross-<arch>-build for the supported archs.'

	@echo  ''
	@echo  'kABI targets:'
	@echo  '  rh-kabi           - Create kABI whitelist files in redhat/kabi/kabi-rhel*/ and'
	@echo  '                      merge kABI checksums into redhat/kabi/Module.kabi_*.'
	@echo  '  rh-kabi-dup       - Merge kABI checksums for Driver Update Program (DUP) whitelist'
	@echo  '                      into redhat/kabi/Module.kabi_dup_*.'
	@echo  '  rh-check-kabi     - Check for changes in kABI whitelisted symbols.'
	@echo  '                      Requires a pre-compiled tree: run `make rh-configs`, copy the'
	@echo  '                      relevant config file from redhat/configs/ to .config, run `make`.'
	@echo  '  rh-check-kabi-dup - Like rh-check-kabi but uses a DUP kABI whitelist.'
	@echo  '  rh-kabi-dw-base   - Generate the base dataset for kABI DWARF-based check.'
	@echo  '  rh-kabi-dw-check  - Run DWARF-based kABI comparison of current binaries with the base'
	@echo  '                      dataset.'

	@echo  ''
	@echo  'Configuration targets:'
	@echo  '  rh-configs  - Creates config files for RHEL $(RHEL_MAJOR) architectures, cleans them'
	@echo  '                by running make nonint_oldconfig, and copies them to'
	@echo  '                redhat/configs/ directory. This is the target to use for a config!'
	@echo  '                Copy the config file you want from the redhat/configs/ directory'
	@echo  '                to .config.'
	@echo  '  rh-configs-arch  - Same as rh-configs but for single architecture only.'

	@echo  ''
	@echo  'Misc targets:'
	@echo  '  rh-get-latest - Returns the latest "known good" kernel from brew. This should not'
	@echo  '                  be confused with the latest top-of-tree development tag.'
	@echo  '  rh-os-version - Displays the current Red Hat Enterprise Linux version target used'
	@echo  '                  by the current branch/tree.'
	@echo  ''
