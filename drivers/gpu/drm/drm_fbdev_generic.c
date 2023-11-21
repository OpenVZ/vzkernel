// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/vmalloc.h>

#include <drm/drm_crtc_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_print.h>

#include <drm/drm_fbdev_generic.h>

static bool drm_fbdev_use_shadow_fb(struct drm_fb_helper *fb_helper)
{
	struct drm_device *dev = fb_helper->dev;
	struct drm_framebuffer *fb = fb_helper->fb;

	return dev->mode_config.prefer_shadow_fbdev ||
	       dev->mode_config.prefer_shadow ||
	       fb->funcs->dirty;
}

/* @user: 1=userspace, 0=fbcon */
static int drm_fbdev_fb_open(struct fb_info *info, int user)
{
	struct drm_fb_helper *fb_helper = info->par;

	/* No need to take a ref for fbcon because it unbinds on unregister */
	if (user && !try_module_get(fb_helper->dev->driver->fops->owner))
		return -ENODEV;

	return 0;
}

static int drm_fbdev_fb_release(struct fb_info *info, int user)
{
	struct drm_fb_helper *fb_helper = info->par;

	if (user)
		module_put(fb_helper->dev->driver->fops->owner);

	return 0;
}

static void drm_fbdev_fb_destroy(struct fb_info *info)
{
	struct drm_fb_helper *fb_helper = info->par;
	void *shadow = NULL;

	if (!fb_helper->dev)
		return;

	if (info->fbdefio)
		fb_deferred_io_cleanup(info);
	if (drm_fbdev_use_shadow_fb(fb_helper))
		shadow = info->screen_buffer;

	drm_fb_helper_fini(fb_helper);

	if (shadow)
		vfree(shadow);
	else if (fb_helper->buffer)
		drm_client_buffer_vunmap(fb_helper->buffer);

	drm_client_framebuffer_delete(fb_helper->buffer);
	drm_client_release(&fb_helper->client);

	drm_fb_helper_unprepare(fb_helper);
	kfree(fb_helper);
}

static int drm_fbdev_fb_mmap(struct fb_info *info, struct vm_area_struct *vma)
{
	struct drm_fb_helper *fb_helper = info->par;

	if (drm_fbdev_use_shadow_fb(fb_helper))
		return fb_deferred_io_mmap(info, vma);
	else if (fb_helper->dev->driver->gem_prime_mmap)
		return fb_helper->dev->driver->gem_prime_mmap(fb_helper->buffer->gem, vma);
	else
		return -ENODEV;
}

static bool drm_fbdev_use_iomem(struct fb_info *info)
{
	struct drm_fb_helper *fb_helper = info->par;
	struct drm_client_buffer *buffer = fb_helper->buffer;

	return !drm_fbdev_use_shadow_fb(fb_helper) && buffer->map.is_iomem;
}

static ssize_t drm_fbdev_fb_read(struct fb_info *info, char __user *buf,
				 size_t count, loff_t *ppos)
{
	ssize_t ret;

	if (drm_fbdev_use_iomem(info))
		ret = drm_fb_helper_cfb_read(info, buf, count, ppos);
	else
		ret = drm_fb_helper_sys_read(info, buf, count, ppos);

	return ret;
}

static ssize_t drm_fbdev_fb_write(struct fb_info *info, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	ssize_t ret;

	if (drm_fbdev_use_iomem(info))
		ret = drm_fb_helper_cfb_write(info, buf, count, ppos);
	else
		ret = drm_fb_helper_sys_write(info, buf, count, ppos);

	return ret;
}

static void drm_fbdev_fb_fillrect(struct fb_info *info,
				  const struct fb_fillrect *rect)
{
	if (drm_fbdev_use_iomem(info))
		drm_fb_helper_cfb_fillrect(info, rect);
	else
		drm_fb_helper_sys_fillrect(info, rect);
}

static void drm_fbdev_fb_copyarea(struct fb_info *info,
				  const struct fb_copyarea *area)
{
	if (drm_fbdev_use_iomem(info))
		drm_fb_helper_cfb_copyarea(info, area);
	else
		drm_fb_helper_sys_copyarea(info, area);
}

static void drm_fbdev_fb_imageblit(struct fb_info *info,
				   const struct fb_image *image)
{
	if (drm_fbdev_use_iomem(info))
		drm_fb_helper_cfb_imageblit(info, image);
	else
		drm_fb_helper_sys_imageblit(info, image);
}

static const struct fb_ops drm_fbdev_fb_ops = {
	.owner		= THIS_MODULE,
	DRM_FB_HELPER_DEFAULT_OPS,
	.fb_open	= drm_fbdev_fb_open,
	.fb_release	= drm_fbdev_fb_release,
	.fb_destroy	= drm_fbdev_fb_destroy,
	.fb_mmap	= drm_fbdev_fb_mmap,
	.fb_read	= drm_fbdev_fb_read,
	.fb_write	= drm_fbdev_fb_write,
	.fb_fillrect	= drm_fbdev_fb_fillrect,
	.fb_copyarea	= drm_fbdev_fb_copyarea,
	.fb_imageblit	= drm_fbdev_fb_imageblit,
};

/*
 * This function uses the client API to create a framebuffer backed by a dumb buffer.
 */
static int drm_fbdev_fb_probe(struct drm_fb_helper *fb_helper,
			      struct drm_fb_helper_surface_size *sizes)
{
	struct drm_client_dev *client = &fb_helper->client;
	struct drm_device *dev = fb_helper->dev;
	struct drm_client_buffer *buffer;
	struct drm_framebuffer *fb;
	struct fb_info *info;
	u32 format;
	struct iosys_map map;
	int ret;

	drm_dbg_kms(dev, "surface width(%d), height(%d) and bpp(%d)\n",
		    sizes->surface_width, sizes->surface_height,
		    sizes->surface_bpp);

	format = drm_mode_legacy_fb_format(sizes->surface_bpp, sizes->surface_depth);
	buffer = drm_client_framebuffer_create(client, sizes->surface_width,
					       sizes->surface_height, format);
	if (IS_ERR(buffer))
		return PTR_ERR(buffer);

	fb_helper->buffer = buffer;
	fb_helper->fb = buffer->fb;
	fb = buffer->fb;

	info = drm_fb_helper_alloc_info(fb_helper);
	if (IS_ERR(info))
		return PTR_ERR(info);

	info->fbops = &drm_fbdev_fb_ops;
	info->screen_size = sizes->surface_height * fb->pitches[0];
	info->fix.smem_len = info->screen_size;
	info->flags = FBINFO_DEFAULT;

	drm_fb_helper_fill_info(info, fb_helper, sizes);

	if (drm_fbdev_use_shadow_fb(fb_helper)) {
		info->screen_buffer = vzalloc(info->screen_size);
		if (!info->screen_buffer)
			return -ENOMEM;
		info->flags |= FBINFO_VIRTFB | FBINFO_READS_FAST;

		/* Set a default deferred I/O handler */
		fb_helper->fbdefio.delay = HZ / 20;
		fb_helper->fbdefio.deferred_io = drm_fb_helper_deferred_io;

		info->fbdefio = &fb_helper->fbdefio;
		ret = fb_deferred_io_init(info);
		if (ret)
			return ret;
	} else {
		/* buffer is mapped for HW framebuffer */
		ret = drm_client_buffer_vmap(fb_helper->buffer, &map);
		if (ret)
			return ret;
		if (map.is_iomem) {
			info->screen_base = map.vaddr_iomem;
		} else {
			info->screen_buffer = map.vaddr;
			info->flags |= FBINFO_VIRTFB;
		}

		/*
		 * Shamelessly leak the physical address to user-space. As
		 * page_to_phys() is undefined for I/O memory, warn in this
		 * case.
		 */
#if IS_ENABLED(CONFIG_DRM_FBDEV_LEAK_PHYS_SMEM)
		if (fb_helper->hint_leak_smem_start && info->fix.smem_start == 0 &&
		    !drm_WARN_ON_ONCE(dev, map.is_iomem))
			info->fix.smem_start =
				page_to_phys(virt_to_page(info->screen_buffer));
#endif
	}

	return 0;
}

static void drm_fbdev_damage_blit_real(struct drm_fb_helper *fb_helper,
				       struct drm_clip_rect *clip,
				       struct iosys_map *dst)
{
	struct drm_framebuffer *fb = fb_helper->fb;
	size_t offset = clip->y1 * fb->pitches[0];
	size_t len = clip->x2 - clip->x1;
	unsigned int y;
	void *src;

	switch (drm_format_info_bpp(fb->format, 0)) {
	case 1:
		offset += clip->x1 / 8;
		len = DIV_ROUND_UP(len + clip->x1 % 8, 8);
		break;
	case 2:
		offset += clip->x1 / 4;
		len = DIV_ROUND_UP(len + clip->x1 % 4, 4);
		break;
	case 4:
		offset += clip->x1 / 2;
		len = DIV_ROUND_UP(len + clip->x1 % 2, 2);
		break;
	default:
		offset += clip->x1 * fb->format->cpp[0];
		len *= fb->format->cpp[0];
		break;
	}

	src = fb_helper->info->screen_buffer + offset;
	iosys_map_incr(dst, offset); /* go to first pixel within clip rect */

	for (y = clip->y1; y < clip->y2; y++) {
		iosys_map_memcpy_to(dst, 0, src, len);
		iosys_map_incr(dst, fb->pitches[0]);
		src += fb->pitches[0];
	}
}

static int drm_fbdev_damage_blit(struct drm_fb_helper *fb_helper,
				 struct drm_clip_rect *clip)
{
	struct drm_client_buffer *buffer = fb_helper->buffer;
	struct iosys_map map, dst;
	int ret;

	/*
	 * We have to pin the client buffer to its current location while
	 * flushing the shadow buffer. In the general case, concurrent
	 * modesetting operations could try to move the buffer and would
	 * fail. The modeset has to be serialized by acquiring the reservation
	 * object of the underlying BO here.
	 *
	 * For fbdev emulation, we only have to protect against fbdev modeset
	 * operations. Nothing else will involve the client buffer's BO. So it
	 * is sufficient to acquire struct drm_fb_helper.lock here.
	 */
	mutex_lock(&fb_helper->lock);

	ret = drm_client_buffer_vmap(buffer, &map);
	if (ret)
		goto out;

	dst = map;
	drm_fbdev_damage_blit_real(fb_helper, clip, &dst);

	drm_client_buffer_vunmap(buffer);

out:
	mutex_unlock(&fb_helper->lock);

	return ret;
}

static int drm_fbdev_fb_dirty(struct drm_fb_helper *helper, struct drm_clip_rect *clip)
{
	struct drm_device *dev = helper->dev;
	int ret;

	if (!drm_fbdev_use_shadow_fb(helper))
		return 0;

	/* Call damage handlers only if necessary */
	if (!(clip->x1 < clip->x2 && clip->y1 < clip->y2))
		return 0;

	if (helper->buffer) {
		ret = drm_fbdev_damage_blit(helper, clip);
		if (drm_WARN_ONCE(dev, ret, "Damage blitter failed: ret=%d\n", ret))
			return ret;
	}

	if (helper->fb->funcs->dirty) {
		ret = helper->fb->funcs->dirty(helper->fb, NULL, 0, 0, clip, 1);
		if (drm_WARN_ONCE(dev, ret, "Dirty helper failed: ret=%d\n", ret))
			return ret;
	}

	return 0;
}

static const struct drm_fb_helper_funcs drm_fb_helper_generic_funcs = {
	.fb_probe = drm_fbdev_fb_probe,
	.fb_dirty = drm_fbdev_fb_dirty,
};

static void drm_fbdev_client_unregister(struct drm_client_dev *client)
{
	struct drm_fb_helper *fb_helper = drm_fb_helper_from_client(client);

	if (fb_helper->info) {
		drm_fb_helper_unregister_info(fb_helper);
	} else {
		drm_client_release(&fb_helper->client);
		drm_fb_helper_unprepare(fb_helper);
		kfree(fb_helper);
	}
}

static int drm_fbdev_client_restore(struct drm_client_dev *client)
{
	drm_fb_helper_lastclose(client->dev);

	return 0;
}

static int drm_fbdev_client_hotplug(struct drm_client_dev *client)
{
	struct drm_fb_helper *fb_helper = drm_fb_helper_from_client(client);
	struct drm_device *dev = client->dev;
	int ret;

	if (dev->fb_helper)
		return drm_fb_helper_hotplug_event(dev->fb_helper);

	ret = drm_fb_helper_init(dev, fb_helper);
	if (ret)
		goto err_drm_err;

	if (!drm_drv_uses_atomic_modeset(dev))
		drm_helper_disable_unused_functions(dev);

	ret = drm_fb_helper_initial_config(fb_helper);
	if (ret)
		goto err_drm_fb_helper_fini;

	return 0;

err_drm_fb_helper_fini:
	drm_fb_helper_fini(fb_helper);
err_drm_err:
	drm_err(dev, "fbdev: Failed to setup generic emulation (ret=%d)\n", ret);
	return ret;
}

static const struct drm_client_funcs drm_fbdev_client_funcs = {
	.owner		= THIS_MODULE,
	.unregister	= drm_fbdev_client_unregister,
	.restore	= drm_fbdev_client_restore,
	.hotplug	= drm_fbdev_client_hotplug,
};

/**
 * drm_fbdev_generic_setup() - Setup generic fbdev emulation
 * @dev: DRM device
 * @preferred_bpp: Preferred bits per pixel for the device.
 *
 * This function sets up generic fbdev emulation for drivers that supports
 * dumb buffers with a virtual address and that can be mmap'ed.
 * drm_fbdev_generic_setup() shall be called after the DRM driver registered
 * the new DRM device with drm_dev_register().
 *
 * Restore, hotplug events and teardown are all taken care of. Drivers that do
 * suspend/resume need to call drm_fb_helper_set_suspend_unlocked() themselves.
 * Simple drivers might use drm_mode_config_helper_suspend().
 *
 * Drivers that set the dirty callback on their framebuffer will get a shadow
 * fbdev buffer that is blitted onto the real buffer. This is done in order to
 * make deferred I/O work with all kinds of buffers. A shadow buffer can be
 * requested explicitly by setting struct drm_mode_config.prefer_shadow or
 * struct drm_mode_config.prefer_shadow_fbdev to true beforehand. This is
 * required to use generic fbdev emulation with SHMEM helpers.
 *
 * This function is safe to call even when there are no connectors present.
 * Setup will be retried on the next hotplug event.
 *
 * The fbdev is destroyed by drm_dev_unregister().
 */
void drm_fbdev_generic_setup(struct drm_device *dev,
			     unsigned int preferred_bpp)
{
	struct drm_fb_helper *fb_helper;
	int ret;

	drm_WARN(dev, !dev->registered, "Device has not been registered.\n");
	drm_WARN(dev, dev->fb_helper, "fb_helper is already set!\n");

	fb_helper = kzalloc(sizeof(*fb_helper), GFP_KERNEL);
	if (!fb_helper)
		return;
	drm_fb_helper_prepare(dev, fb_helper, preferred_bpp, &drm_fb_helper_generic_funcs);

	ret = drm_client_init(dev, &fb_helper->client, "fbdev", &drm_fbdev_client_funcs);
	if (ret) {
		drm_err(dev, "Failed to register client: %d\n", ret);
		goto err_drm_client_init;
	}

	ret = drm_fbdev_client_hotplug(&fb_helper->client);
	if (ret)
		drm_dbg_kms(dev, "client hotplug ret=%d\n", ret);

	drm_client_register(&fb_helper->client);

	return;

err_drm_client_init:
	drm_fb_helper_unprepare(fb_helper);
	kfree(fb_helper);
	return;
}
EXPORT_SYMBOL(drm_fbdev_generic_setup);
