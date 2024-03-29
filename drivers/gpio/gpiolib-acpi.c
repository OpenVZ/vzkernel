/*
 * ACPI helpers for GPIO API
 *
 * Copyright (C) 2012, Intel Corporation
 * Authors: Mathias Nyman <mathias.nyman@linux.intel.com>
 *          Mika Westerberg <mika.westerberg@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/errno.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio/driver.h>
#include <linux/export.h>
#include <linux/acpi.h>
#include <linux/interrupt.h>

#include "gpiolib.h"

struct acpi_gpio_evt_pin {
	struct list_head node;
	acpi_handle *evt_handle;
	unsigned int pin;
	unsigned int irq;
};

static int acpi_gpiochip_find(struct gpio_chip *gc, void *data)
{
	if (!gc->dev)
		return false;

	return ACPI_HANDLE(gc->dev) == data;
}

/**
 * acpi_get_gpiod() - Translate ACPI GPIO pin to GPIO descriptor usable with GPIO API
 * @path:	ACPI GPIO controller full path name, (e.g. "\\_SB.GPO1")
 * @pin:	ACPI GPIO pin number (0-based, controller-relative)
 *
 * Return: GPIO descriptor to use with Linux generic GPIO API, or ERR_PTR
 * error value. Specifically returns %-EPROBE_DEFER if the referenced GPIO
 * controller does not have gpiochip registered at the moment. This is to
 * support probe deferral.
 */
static struct gpio_desc *acpi_get_gpiod(char *path, int pin)
{
	struct gpio_chip *chip;
	acpi_handle handle;
	acpi_status status;

	status = acpi_get_handle(NULL, path, &handle);
	if (ACPI_FAILURE(status))
		return ERR_PTR(-ENODEV);

	chip = gpiochip_find(handle, acpi_gpiochip_find);
	if (!chip)
		return ERR_PTR(-EPROBE_DEFER);

	if (pin < 0 || pin > chip->ngpio)
		return ERR_PTR(-EINVAL);

	return gpio_to_desc(chip->base + pin);
}

static irqreturn_t acpi_gpio_irq_handler(int irq, void *data)
{
	acpi_handle handle = data;

	acpi_evaluate_object(handle, NULL, NULL, NULL);

	return IRQ_HANDLED;
}

static irqreturn_t acpi_gpio_irq_handler_evt(int irq, void *data)
{
	struct acpi_gpio_evt_pin *evt_pin = data;

	acpi_execute_simple_method(evt_pin->evt_handle, NULL, evt_pin->pin);

	return IRQ_HANDLED;
}

static void acpi_gpio_evt_dh(acpi_handle handle, void *data)
{
	/* The address of this function is used as a key. */
}

/**
 * acpi_gpiochip_request_interrupts() - Register isr for gpio chip ACPI events
 * @chip:      gpio chip
 *
 * ACPI5 platforms can use GPIO signaled ACPI events. These GPIO interrupts are
 * handled by ACPI event methods which need to be called from the GPIO
 * chip's interrupt handler. acpi_gpiochip_request_interrupts finds out which
 * gpio pins have acpi event methods and assigns interrupt handlers that calls
 * the acpi event methods for those pins.
 */
static void acpi_gpiochip_request_interrupts(struct gpio_chip *chip)
{
	struct acpi_buffer buf = {ACPI_ALLOCATE_BUFFER, NULL};
	struct acpi_resource *res;
	acpi_handle handle, evt_handle;
	struct list_head *evt_pins = NULL;
	acpi_status status;
	unsigned int pin;
	int irq, ret;
	char ev_name[5];

	if (!chip->dev || !chip->to_irq)
		return;

	handle = ACPI_HANDLE(chip->dev);
	if (!handle)
		return;

	status = acpi_get_event_resources(handle, &buf);
	if (ACPI_FAILURE(status))
		return;

	status = acpi_get_handle(handle, "_EVT", &evt_handle);
	if (ACPI_SUCCESS(status)) {
		evt_pins = kzalloc(sizeof(*evt_pins), GFP_KERNEL);
		if (evt_pins) {
			INIT_LIST_HEAD(evt_pins);
			status = acpi_attach_data(handle, acpi_gpio_evt_dh,
						  evt_pins);
			if (ACPI_FAILURE(status)) {
				kfree(evt_pins);
				evt_pins = NULL;
			}
		}
	}

	/*
	 * If a GPIO interrupt has an ACPI event handler method, or _EVT is
	 * present, set up an interrupt handler that calls the ACPI event
	 * handler.
	 */
	for (res = buf.pointer;
	     res && (res->type != ACPI_RESOURCE_TYPE_END_TAG);
	     res = ACPI_NEXT_RESOURCE(res)) {
		irq_handler_t handler = NULL;
		void *data;

		if (res->type != ACPI_RESOURCE_TYPE_GPIO ||
		    res->data.gpio.connection_type !=
		    ACPI_RESOURCE_GPIO_TYPE_INT)
			continue;

		pin = res->data.gpio.pin_table[0];
		if (pin > chip->ngpio)
			continue;

		irq = chip->to_irq(chip, pin);
		if (irq < 0)
			continue;

		if (pin <= 255) {
			acpi_handle ev_handle;

			sprintf(ev_name, "_%c%02X",
				res->data.gpio.triggering ? 'E' : 'L', pin);
			status = acpi_get_handle(handle, ev_name, &ev_handle);
			if (ACPI_SUCCESS(status)) {
				handler = acpi_gpio_irq_handler;
				data = ev_handle;
			}
		}
		if (!handler && evt_pins) {
			struct acpi_gpio_evt_pin *evt_pin;

			evt_pin = kzalloc(sizeof(*evt_pin), GFP_KERNEL);
			if (!evt_pin)
				continue;

			list_add_tail(&evt_pin->node, evt_pins);
			evt_pin->evt_handle = evt_handle;
			evt_pin->pin = pin;
			evt_pin->irq = irq;
			handler = acpi_gpio_irq_handler_evt;
			data = evt_pin;
		}
		if (!handler)
			continue;

		/* Assume BIOS sets the triggering, so no flags */
		ret = devm_request_threaded_irq(chip->dev, irq, NULL, handler,
						0, "GPIO-signaled-ACPI-event",
						data);
		if (ret)
			dev_err(chip->dev,
				"Failed to request IRQ %d ACPI event handler\n",
				irq);
	}
}

/**
 * acpi_gpiochip_free_interrupts() - Free GPIO _EVT ACPI event interrupts.
 * @chip:      gpio chip
 *
 * Free interrupts associated with the _EVT method for the given GPIO chip.
 *
 * The remaining ACPI event interrupts associated with the chip are freed
 * automatically.
 */
static void acpi_gpiochip_free_interrupts(struct gpio_chip *chip)
{
	acpi_handle handle;
	acpi_status status;
	struct list_head *evt_pins;
	struct acpi_gpio_evt_pin *evt_pin, *ep;

	if (!chip->dev || !chip->to_irq)
		return;

	handle = ACPI_HANDLE(chip->dev);
	if (!handle)
		return;

	status = acpi_get_data(handle, acpi_gpio_evt_dh, (void **)&evt_pins);
	if (ACPI_FAILURE(status))
		return;

	list_for_each_entry_safe_reverse(evt_pin, ep, evt_pins, node) {
		devm_free_irq(chip->dev, evt_pin->irq, evt_pin);
		list_del(&evt_pin->node);
		kfree(evt_pin);
	}

	acpi_detach_data(handle, acpi_gpio_evt_dh);
	kfree(evt_pins);
}

int acpi_dev_add_driver_gpios(struct acpi_device *adev,
			      const struct acpi_gpio_mapping *gpios)
{
	if (adev && gpios) {
		adev->driver_gpios = gpios;
		return 0;
	}
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(acpi_dev_add_driver_gpios);

static void devm_acpi_dev_release_driver_gpios(struct device *dev, void *res)
{
	acpi_dev_remove_driver_gpios(ACPI_COMPANION(dev));
}

int devm_acpi_dev_add_driver_gpios(struct device *dev,
				   const struct acpi_gpio_mapping *gpios)
{
	void *res;
	int ret;

	res = devres_alloc(devm_acpi_dev_release_driver_gpios, 0, GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	ret = acpi_dev_add_driver_gpios(ACPI_COMPANION(dev), gpios);
	if (ret) {
		devres_free(res);
		return ret;
	}
	devres_add(dev, res);
	return 0;
}
EXPORT_SYMBOL_GPL(devm_acpi_dev_add_driver_gpios);

void devm_acpi_dev_remove_driver_gpios(struct device *dev)
{
	WARN_ON(devres_release(dev, devm_acpi_dev_release_driver_gpios, NULL, NULL));
}
EXPORT_SYMBOL_GPL(devm_acpi_dev_remove_driver_gpios);

static bool acpi_get_driver_gpio_data(struct acpi_device *adev,
				      const char *name, int index,
				      struct acpi_reference_args *args)
{
	const struct acpi_gpio_mapping *gm;

	if (!adev->driver_gpios)
		return false;

	for (gm = adev->driver_gpios; gm->name; gm++)
		if (!strcmp(name, gm->name) && gm->data && index < gm->size) {
			const struct acpi_gpio_params *par = gm->data + index;

			args->adev = adev;
			args->args[0] = par->crs_entry_index;
			args->args[1] = par->line_index;
			args->args[2] = par->active_low;
			args->nargs = 3;
			return true;
		}

	return false;
}

struct acpi_gpio_lookup {
	struct acpi_gpio_info info;
	int index;
	int pin_index;
	struct gpio_desc *desc;
	int n;
};

static int acpi_find_gpio(struct acpi_resource *ares, void *data)
{
	struct acpi_gpio_lookup *lookup = data;

	if (ares->type != ACPI_RESOURCE_TYPE_GPIO)
		return 1;

	if (lookup->n++ == lookup->index && !lookup->desc) {
		const struct acpi_resource_gpio *agpio = &ares->data.gpio;
		int pin_index = lookup->pin_index;

		if (pin_index >= agpio->pin_table_length)
			return 1;

		lookup->desc = acpi_get_gpiod(agpio->resource_source.string_ptr,
					      agpio->pin_table[pin_index]);
		lookup->info.gpioint =
			agpio->connection_type == ACPI_RESOURCE_GPIO_TYPE_INT;

		/*
		 * ActiveLow is only specified for GpioInt resource. If
		 * GpioIo is used then the only way to set the flag is
		 * to use _DSD "gpios" property.
		 */
		if (lookup->info.gpioint)
			lookup->info.active_low =
				agpio->polarity == ACPI_ACTIVE_LOW;
	}

	return 1;
}

/**
 * acpi_get_gpiod_by_index() - get a GPIO descriptor from device resources
 * @adev: pointer to a ACPI device to get GPIO from
 * @propname: Property name of the GPIO (optional)
 * @index: index of GpioIo/GpioInt resource (starting from %0)
 * @info: info pointer to fill in (optional)
 *
 * Function goes through ACPI resources for @adev and based on @index looks
 * up a GpioIo/GpioInt resource, translates it to the Linux GPIO descriptor,
 * and returns it. @index matches GpioIo/GpioInt resources only so if there
 * are total %3 GPIO resources, the index goes from %0 to %2.
 *
 * If @propname is specified the GPIO is looked using device property. In
 * that case @index is used to select the GPIO entry in the property value
 * (in case of multiple).
 *
 * If the GPIO cannot be translated or there is an error an ERR_PTR is
 * returned.
 *
 * Note: if the GPIO resource has multiple entries in the pin list, this
 * function only returns the first.
 */
struct gpio_desc *acpi_get_gpiod_by_index(struct acpi_device *adev,
					  const char *propname, int index,
					  struct acpi_gpio_info *info)
{
	struct acpi_gpio_lookup lookup;
	struct list_head resource_list;
	bool active_low = false;
	int ret;

	if (!adev)
		return ERR_PTR(-ENODEV);

	memset(&lookup, 0, sizeof(lookup));
	lookup.index = index;

	if (propname) {
		struct acpi_reference_args args;

		dev_dbg(&adev->dev, "GPIO: looking up %s\n", propname);

		memset(&args, 0, sizeof(args));
		ret = acpi_node_get_property_reference(acpi_fwnode_handle(adev),
						       propname, index, &args);
		if (ret) {
			bool found = acpi_get_driver_gpio_data(adev, propname,
							       index, &args);
			if (!found)
				return ERR_PTR(ret);
		}

		/*
		 * The property was found and resolved so need to
		 * lookup the GPIO based on returned args instead.
		 */
		adev = args.adev;
		if (args.nargs >= 2) {
			lookup.index = args.args[0];
			lookup.pin_index = args.args[1];
			/*
			 * 3rd argument, if present is used to
			 * specify active_low.
			 */
			if (args.nargs >= 3)
				active_low = !!args.args[2];
		}

		dev_dbg(&adev->dev, "GPIO: _DSD returned %s %zd %llu %llu %llu\n",
			dev_name(&adev->dev), args.nargs,
			args.args[0], args.args[1], args.args[2]);
	} else {
		dev_dbg(&adev->dev, "GPIO: looking up %d in _CRS\n", index);
	}

	INIT_LIST_HEAD(&resource_list);
	ret = acpi_dev_get_resources(adev, &resource_list, acpi_find_gpio,
				     &lookup);
	if (ret < 0)
		return ERR_PTR(ret);

	acpi_dev_free_resource_list(&resource_list);

	if (lookup.desc && info) {
		*info = lookup.info;
		if (active_low)
			info->active_low = active_low;
	}

	return lookup.desc ? lookup.desc : ERR_PTR(-ENOENT);
}

/**
 * acpi_dev_gpio_irq_get() - Find GpioInt and translate it to Linux IRQ number
 * @adev: pointer to a ACPI device to get IRQ from
 * @index: index of GpioInt resource (starting from %0)
 *
 * If the device has one or more GpioInt resources, this function can be
 * used to translate from the GPIO offset in the resource to the Linux IRQ
 * number.
 *
 * Return: Linux IRQ number (>%0) on success, negative errno on failure.
 */
int acpi_dev_gpio_irq_get(struct acpi_device *adev, int index)
{
	int idx, i;

	for (i = 0, idx = 0; idx <= index; i++) {
		struct acpi_gpio_info info;
		struct gpio_desc *desc;

		desc = acpi_get_gpiod_by_index(adev, NULL, i, &info);
		if (IS_ERR(desc))
			break;
		if (info.gpioint && idx++ == index)
			return gpiod_to_irq(desc);
	}
	return -ENOENT;
}
EXPORT_SYMBOL_GPL(acpi_dev_gpio_irq_get);

void acpi_gpiochip_add(struct gpio_chip *chip)
{
	acpi_gpiochip_request_interrupts(chip);
}

void acpi_gpiochip_remove(struct gpio_chip *chip)
{
	acpi_gpiochip_free_interrupts(chip);
}
