/*
 * Driver core interface to the pinctrl subsystem.
 *
 * Copyright (C) 2012 ST-Ericsson SA
 * Written on behalf of Linaro for ST-Ericsson
 * Based on bits of regulator core, gpio core and clk core
 *
 * Author: Linus Walleij <linus.walleij@linaro.org>
 *
 * License terms: GNU General Public License (GPL) version 2
 */

#include <linux/device.h>
#include <linux/pinctrl/devinfo.h>
#include <linux/pinctrl/consumer.h>
#include <linux/slab.h>

/**
 * pinctrl_bind_pins() - called by the device core before probe
 * @dev: the device that is just about to probe
 */
int pinctrl_bind_pins(struct device *dev)
{
	int ret;

	dev->device_rh->pins = devm_kzalloc(dev, sizeof(*(dev->device_rh->pins)), GFP_KERNEL);
	if (!dev->device_rh->pins)
		return -ENOMEM;

	dev->device_rh->pins->p = devm_pinctrl_get(dev);
	if (IS_ERR(dev->device_rh->pins->p)) {
		dev_dbg(dev, "no pinctrl handle\n");
		ret = PTR_ERR(dev->device_rh->pins->p);
		goto cleanup_alloc;
	}

	dev->device_rh->pins->default_state = pinctrl_lookup_state(dev->device_rh->pins->p,
					PINCTRL_STATE_DEFAULT);
	if (IS_ERR(dev->device_rh->pins->default_state)) {
		dev_dbg(dev, "no default pinctrl state\n");
		ret = 0;
		goto cleanup_get;
	}

	ret = pinctrl_select_state(dev->device_rh->pins->p, dev->device_rh->pins->default_state);
	if (ret) {
		dev_dbg(dev, "failed to activate default pinctrl state\n");
		goto cleanup_get;
	}

#ifdef CONFIG_PM
	/*
	 * If power management is enabled, we also look for the optional
	 * sleep and idle pin states, with semantics as defined in
	 * <linux/pinctrl/pinctrl-state.h>
	 */
	dev->device_rh->pins->sleep_state = pinctrl_lookup_state(dev->device_rh->pins->p,
						PINCTRL_STATE_SLEEP);
	if (IS_ERR(dev->device_rh->pins->sleep_state))
		/* Not supplying this state is perfectly legal */
		dev_dbg(dev, "no sleep pinctrl state\n");

	dev->device_rh->pins->idle_state = pinctrl_lookup_state(dev->device_rh->pins->p,
						PINCTRL_STATE_IDLE);
	if (IS_ERR(dev->device_rh->pins->idle_state))
		/* Not supplying this state is perfectly legal */
		dev_dbg(dev, "no idle pinctrl state\n");
#endif

	return 0;

	/*
	 * If no pinctrl handle or default state was found for this device,
	 * let's explicitly free the pin container in the device, there is
	 * no point in keeping it around.
	 */
cleanup_get:
	devm_pinctrl_put(dev->device_rh->pins->p);
cleanup_alloc:
	devm_kfree(dev, dev->device_rh->pins);
	dev->device_rh->pins = NULL;

	/* Only return deferrals */
	if (ret != -EPROBE_DEFER)
		ret = 0;

	return ret;
}
