ifeq ($(filter rh-% rhg-%,$(MAKECMDGOALS)),)
	include Makefile
endif

_OUTPUT := "."
# this section is needed in order to make O= to work
ifeq ("$(origin O)", "command line")
  _OUTPUT := "$(abspath $(O))"
  _EXTRA_ARGS := O=$(_OUTPUT)
endif
rh-%::
	$(MAKE) -C redhat $(@) $(_EXTRA_ARGS)

rhg-%::
	$(MAKE) -C redhat $(@) $(_EXTRA_ARGS)

