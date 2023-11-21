/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022-2023 Intel Corporation
 */

#ifndef __INTEL_VBLANK_H__
#define __INTEL_VBLANK_H__

#include <linux/ktime.h>
#include <linux/types.h>

struct drm_crtc;
struct intel_crtc;

u32 i915_get_vblank_counter(struct drm_crtc *crtc);
u32 g4x_get_vblank_counter(struct drm_crtc *crtc);
bool intel_crtc_get_vblank_timestamp(struct drm_crtc *crtc, int *max_error,
				     ktime_t *vblank_time, bool in_vblank_irq);
int intel_get_crtc_scanline(struct intel_crtc *crtc);
void intel_wait_for_pipe_scanline_stopped(struct intel_crtc *crtc);
void intel_wait_for_pipe_scanline_moving(struct intel_crtc *crtc);

#endif /* __INTEL_VBLANK_H__ */
