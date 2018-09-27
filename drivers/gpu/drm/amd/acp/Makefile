#
# Makefile for the ACP, which is a sub-component
# of AMDSOC/AMDGPU drm driver.
# It provides the HW control for ACP related functionalities.

subdir-ccflags-y += -I$(AMDACPPATH)/ -I$(AMDACPPATH)/include
subdir-ccflags-y += -include drm/drm_backport.h

AMD_ACP_FILES := $(AMDACPPATH)/acp_hw.o
