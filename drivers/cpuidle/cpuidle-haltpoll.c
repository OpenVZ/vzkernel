// SPDX-License-Identifier: GPL-2.0
/*
 * cpuidle driver for haltpoll governor.
 *
 * Copyright 2019 Red Hat, Inc. and/or its affiliates.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Authors: Marcelo Tosatti <mtosatti@redhat.com>
 */

#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kvm_para.h>
#include <linux/cpuidle_haltpoll.h>

static struct cpuidle_device __percpu *haltpoll_cpuidle_devices;

static int default_enter_idle(struct cpuidle_device *dev,
			      struct cpuidle_driver *drv, int index)
{
	if (current_clr_polling_and_test()) {
		local_irq_enable();
		return index;
	}
	default_idle();
	return index;
}

static struct cpuidle_driver haltpoll_driver = {
	.name = "haltpoll",
	.owner = THIS_MODULE,
	.states = {
		{ /* entry 0 is for polling */ },
		{
			.enter			= default_enter_idle,
			.exit_latency		= 1,
			.target_residency	= 1,
			.power_usage		= -1,
			.name			= "haltpoll idle",
			.desc			= "default architecture idle",
		},
	},
	.safe_state_index = 0,
	.state_count = 2,
};

static int haltpoll_cpuidle_add_cpu_notifier(struct notifier_block *n,
					     unsigned long action, void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	struct cpuidle_device *dev =
		per_cpu_ptr(haltpoll_cpuidle_devices, hotcpu);

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_ONLINE:
		dev->cpu = hotcpu;
		cpuidle_pause_and_lock();
		cpuidle_enable_device(dev);
		cpuidle_resume_and_unlock();
		arch_haltpoll_enable(hotcpu);

		break;

	case CPU_DEAD:
		cpuidle_pause_and_lock();
		cpuidle_disable_device(dev);
		cpuidle_resume_and_unlock();
		arch_haltpoll_disable(hotcpu);

		break;
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

static struct notifier_block cpu_hotplug_notifier = {
	.notifier_call = haltpoll_cpuidle_add_cpu_notifier,
};

static int haltpoll_cpu_init(unsigned int cpu)
{
	int ret;
	struct cpuidle_device *dev;
	dev = per_cpu_ptr(haltpoll_cpuidle_devices, cpu);

	dev->cpu = cpu;
	ret = cpuidle_register_device(dev);
	if (ret)
		return ret;

	arch_haltpoll_enable(cpu);

	return 0;
}

static void haltpoll_devices_uninit(void)
{
	int i;
	struct cpuidle_device *dev;

	for_each_possible_cpu(i) {
		dev = per_cpu_ptr(haltpoll_cpuidle_devices, i);
		if (dev->registered)
			cpuidle_unregister_device(dev);
		arch_haltpoll_disable(i);
	}
}
static int __init haltpoll_init(void)
{
	int ret, i;

	if (!kvm_para_available())
		return -ENODEV;

	ret = cpuidle_register_driver(&haltpoll_driver);
	if (ret < 0)
		return ret;

	haltpoll_cpuidle_devices = alloc_percpu(struct cpuidle_device);
	if (haltpoll_cpuidle_devices == NULL) {
		cpuidle_unregister_driver(&haltpoll_driver);
		return -ENOMEM;
	}

	cpu_notifier_register_begin();

	for_each_online_cpu(i) {
		ret = haltpoll_cpu_init(i);
		if (ret) {
			haltpoll_devices_uninit();
			cpu_notifier_register_done();
			cpuidle_unregister_driver(&haltpoll_driver);
			free_percpu(haltpoll_cpuidle_devices);
			haltpoll_cpuidle_devices = NULL;
			return ret;
		}
	}

	__register_cpu_notifier(&cpu_hotplug_notifier);

	cpu_notifier_register_done();

	return 0;
}

static void __exit haltpoll_exit(void)
{
	unregister_cpu_notifier(&cpu_hotplug_notifier);
	haltpoll_devices_uninit();
	cpuidle_unregister_driver(&haltpoll_driver);

	free_percpu(haltpoll_cpuidle_devices);
	haltpoll_cpuidle_devices = NULL;
}

module_init(haltpoll_init);
module_exit(haltpoll_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcelo Tosatti <mtosatti@redhat.com>");

