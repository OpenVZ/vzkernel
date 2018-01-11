/*******************************************************************************
 * Filename:  target_core_stat.c
 *
 * Modern ConfigFS group context specific statistics based on original
 * target_core_mib.c code
 *
 * (c) Copyright 2006-2013 Datera, Inc.
 *
 * Nicholas A. Bellinger <nab@linux-iscsi.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ******************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/configfs.h>
#include <linux/ctype.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>

#include "target_core_internal.h"

#ifndef INITIAL_JIFFIES
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#endif

#define NONE		"None"
#define ISPRINT(a)   ((a >= ' ') && (a <= '~'))

#define SCSI_LU_INDEX			1
#define LU_COUNT			1

/*
 * SCSI Device Table
 */

static struct se_device *to_stat_dev(struct config_item *item)
{
	struct se_dev_stat_grps *sgrps = container_of(to_config_group(item),
			struct se_dev_stat_grps, scsi_dev_group);
	return container_of(sgrps, struct se_device, dev_stat_grps);
}

static ssize_t target_stat_inst_show(struct config_item *item, char *page)
{
	struct se_hba *hba = to_stat_dev(item)->se_hba;

	return snprintf(page, PAGE_SIZE, "%u\n", hba->hba_index);
}

static ssize_t target_stat_indx_show(struct config_item *item, char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n", to_stat_dev(item)->dev_index);
}

static ssize_t target_stat_role_show(struct config_item *item, char *page)
{
	return snprintf(page, PAGE_SIZE, "Target\n");
}

static ssize_t target_stat_ports_show(struct config_item *item, char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n", to_stat_dev(item)->export_count);
}

CONFIGFS_ATTR_RO(target_stat_, inst);
CONFIGFS_ATTR_RO(target_stat_, indx);
CONFIGFS_ATTR_RO(target_stat_, role);
CONFIGFS_ATTR_RO(target_stat_, ports);

static struct configfs_attribute *target_stat_scsi_dev_attrs[] = {
	&target_stat_attr_inst,
	&target_stat_attr_indx,
	&target_stat_attr_role,
	&target_stat_attr_ports,
	NULL,
};

static struct config_item_type target_stat_scsi_dev_cit = {
	.ct_attrs		= target_stat_scsi_dev_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * SCSI Target Device Table
 */
static struct se_device *to_stat_tgt_dev(struct config_item *item)
{
	struct se_dev_stat_grps *sgrps = container_of(to_config_group(item),
			struct se_dev_stat_grps, scsi_tgt_dev_group);
	return container_of(sgrps, struct se_device, dev_stat_grps);
}

static ssize_t target_stat_tgt_inst_show(struct config_item *item, char *page)
{
	struct se_hba *hba = to_stat_tgt_dev(item)->se_hba;

	return snprintf(page, PAGE_SIZE, "%u\n", hba->hba_index);
}

static ssize_t target_stat_tgt_indx_show(struct config_item *item, char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n", to_stat_tgt_dev(item)->dev_index);
}

static ssize_t target_stat_tgt_num_lus_show(struct config_item *item,
		char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n", LU_COUNT);
}

static ssize_t target_stat_tgt_status_show(struct config_item *item,
		char *page)
{
	if (to_stat_tgt_dev(item)->export_count)
		return snprintf(page, PAGE_SIZE, "activated");
	else
		return snprintf(page, PAGE_SIZE, "deactivated");
}

static ssize_t target_stat_tgt_non_access_lus_show(struct config_item *item,
		char *page)
{
	int non_accessible_lus;

	if (to_stat_tgt_dev(item)->export_count)
		non_accessible_lus = 0;
	else
		non_accessible_lus = 1;

	return snprintf(page, PAGE_SIZE, "%u\n", non_accessible_lus);
}

static ssize_t target_stat_tgt_resets_show(struct config_item *item,
		char *page)
{
	return snprintf(page, PAGE_SIZE, "%lu\n",
			atomic_long_read(&to_stat_tgt_dev(item)->num_resets));
}

static ssize_t target_stat_tgt_aborts_complete_show(struct config_item *item,
		char *page)
{
	return snprintf(page, PAGE_SIZE, "%lu\n",
			atomic_long_read(&to_stat_tgt_dev(item)->aborts_complete));
}

static ssize_t target_stat_tgt_aborts_no_task_show(struct config_item *item,
		char *page)
{
	return snprintf(page, PAGE_SIZE, "%lu\n",
			atomic_long_read(&to_stat_tgt_dev(item)->aborts_no_task));
}

CONFIGFS_ATTR_RO(target_stat_tgt_, inst);
CONFIGFS_ATTR_RO(target_stat_tgt_, indx);
CONFIGFS_ATTR_RO(target_stat_tgt_, num_lus);
CONFIGFS_ATTR_RO(target_stat_tgt_, status);
CONFIGFS_ATTR_RO(target_stat_tgt_, non_access_lus);
CONFIGFS_ATTR_RO(target_stat_tgt_, resets);
CONFIGFS_ATTR_RO(target_stat_tgt_, aborts_complete);
CONFIGFS_ATTR_RO(target_stat_tgt_, aborts_no_task);

static struct configfs_attribute *target_stat_scsi_tgt_dev_attrs[] = {
	&target_stat_tgt_attr_inst,
	&target_stat_tgt_attr_indx,
	&target_stat_tgt_attr_num_lus,
	&target_stat_tgt_attr_status,
	&target_stat_tgt_attr_non_access_lus,
	&target_stat_tgt_attr_resets,
	&target_stat_tgt_attr_aborts_complete,
	&target_stat_tgt_attr_aborts_no_task,
	NULL,
};

static struct config_item_type target_stat_scsi_tgt_dev_cit = {
	.ct_attrs		= target_stat_scsi_tgt_dev_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * SCSI Logical Unit Table
 */

static struct se_device *to_stat_lu_dev(struct config_item *item)
{
	struct se_dev_stat_grps *sgrps = container_of(to_config_group(item),
			struct se_dev_stat_grps, scsi_lu_group);
	return container_of(sgrps, struct se_device, dev_stat_grps);
}

static ssize_t target_stat_lu_inst_show(struct config_item *item, char *page)
{
	struct se_hba *hba = to_stat_lu_dev(item)->se_hba;

	return snprintf(page, PAGE_SIZE, "%u\n", hba->hba_index);
}

static ssize_t target_stat_lu_dev_show(struct config_item *item, char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n",
			to_stat_lu_dev(item)->dev_index);
}

static ssize_t target_stat_lu_indx_show(struct config_item *item, char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n", SCSI_LU_INDEX);
}

static ssize_t target_stat_lu_lun_show(struct config_item *item, char *page)
{
	/* FIXME: scsiLuDefaultLun */
	return snprintf(page, PAGE_SIZE, "%llu\n", (unsigned long long)0);
}

static ssize_t target_stat_lu_lu_name_show(struct config_item *item, char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);

	/* scsiLuWwnName */
	return snprintf(page, PAGE_SIZE, "%s\n",
			(strlen(dev->t10_wwn.unit_serial)) ?
			dev->t10_wwn.unit_serial : "None");
}

static ssize_t target_stat_lu_vend_show(struct config_item *item, char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);
	int i;
	char str[sizeof(dev->t10_wwn.vendor)+1];

	/* scsiLuVendorId */
	for (i = 0; i < sizeof(dev->t10_wwn.vendor); i++)
		str[i] = ISPRINT(dev->t10_wwn.vendor[i]) ?
			dev->t10_wwn.vendor[i] : ' ';
	str[i] = '\0';
	return snprintf(page, PAGE_SIZE, "%s\n", str);
}

static ssize_t target_stat_lu_prod_show(struct config_item *item, char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);
	int i;
	char str[sizeof(dev->t10_wwn.model)+1];

	/* scsiLuProductId */
	for (i = 0; i < sizeof(dev->t10_wwn.model); i++)
		str[i] = ISPRINT(dev->t10_wwn.model[i]) ?
			dev->t10_wwn.model[i] : ' ';
	str[i] = '\0';
	return snprintf(page, PAGE_SIZE, "%s\n", str);
}

static ssize_t target_stat_lu_rev_show(struct config_item *item, char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);
	int i;
	char str[sizeof(dev->t10_wwn.revision)+1];

	/* scsiLuRevisionId */
	for (i = 0; i < sizeof(dev->t10_wwn.revision); i++)
		str[i] = ISPRINT(dev->t10_wwn.revision[i]) ?
			dev->t10_wwn.revision[i] : ' ';
	str[i] = '\0';
	return snprintf(page, PAGE_SIZE, "%s\n", str);
}

static ssize_t target_stat_lu_dev_type_show(struct config_item *item, char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);

	/* scsiLuPeripheralType */
	return snprintf(page, PAGE_SIZE, "%u\n",
			dev->transport->get_device_type(dev));
}

static ssize_t target_stat_lu_status_show(struct config_item *item, char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);

	/* scsiLuStatus */
	return snprintf(page, PAGE_SIZE, "%s\n",
		(dev->export_count) ? "available" : "notavailable");
}

static ssize_t target_stat_lu_state_bit_show(struct config_item *item,
		char *page)
{
	/* scsiLuState */
	return snprintf(page, PAGE_SIZE, "exposed\n");
}

static ssize_t target_stat_lu_num_cmds_show(struct config_item *item,
		char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);

	/* scsiLuNumCommands */
	return snprintf(page, PAGE_SIZE, "%lu\n",
			atomic_long_read(&dev->num_cmds));
}

static ssize_t target_stat_lu_read_mbytes_show(struct config_item *item,
		char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);

	/* scsiLuReadMegaBytes */
	return snprintf(page, PAGE_SIZE, "%lu\n",
			atomic_long_read(&dev->read_bytes) >> 20);
}

static ssize_t target_stat_lu_write_mbytes_show(struct config_item *item,
		char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);

	/* scsiLuWrittenMegaBytes */
	return snprintf(page, PAGE_SIZE, "%lu\n",
			atomic_long_read(&dev->write_bytes) >> 20);
}

static ssize_t target_stat_lu_resets_show(struct config_item *item, char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);

	/* scsiLuInResets */
	return snprintf(page, PAGE_SIZE, "%lu\n",
		atomic_long_read(&dev->num_resets));
}

static ssize_t target_stat_lu_full_stat_show(struct config_item *item,
		char *page)
{
	/* FIXME: scsiLuOutTaskSetFullStatus */
	return snprintf(page, PAGE_SIZE, "%u\n", 0);
}

static ssize_t target_stat_lu_hs_num_cmds_show(struct config_item *item,
		char *page)
{
	/* FIXME: scsiLuHSInCommands */
	return snprintf(page, PAGE_SIZE, "%u\n", 0);
}

static ssize_t target_stat_lu_creation_time_show(struct config_item *item,
		char *page)
{
	struct se_device *dev = to_stat_lu_dev(item);

	/* scsiLuCreationTime */
	return snprintf(page, PAGE_SIZE, "%u\n", (u32)(((u32)dev->creation_time -
				INITIAL_JIFFIES) * 100 / HZ));
}

CONFIGFS_ATTR_RO(target_stat_lu_, inst);
CONFIGFS_ATTR_RO(target_stat_lu_, dev);
CONFIGFS_ATTR_RO(target_stat_lu_, indx);
CONFIGFS_ATTR_RO(target_stat_lu_, lun);
CONFIGFS_ATTR_RO(target_stat_lu_, lu_name);
CONFIGFS_ATTR_RO(target_stat_lu_, vend);
CONFIGFS_ATTR_RO(target_stat_lu_, prod);
CONFIGFS_ATTR_RO(target_stat_lu_, rev);
CONFIGFS_ATTR_RO(target_stat_lu_, dev_type);
CONFIGFS_ATTR_RO(target_stat_lu_, status);
CONFIGFS_ATTR_RO(target_stat_lu_, state_bit);
CONFIGFS_ATTR_RO(target_stat_lu_, num_cmds);
CONFIGFS_ATTR_RO(target_stat_lu_, read_mbytes);
CONFIGFS_ATTR_RO(target_stat_lu_, write_mbytes);
CONFIGFS_ATTR_RO(target_stat_lu_, resets);
CONFIGFS_ATTR_RO(target_stat_lu_, full_stat);
CONFIGFS_ATTR_RO(target_stat_lu_, hs_num_cmds);
CONFIGFS_ATTR_RO(target_stat_lu_, creation_time);

static struct configfs_attribute *target_stat_scsi_lu_attrs[] = {
	&target_stat_lu_attr_inst,
	&target_stat_lu_attr_dev,
	&target_stat_lu_attr_indx,
	&target_stat_lu_attr_lun,
	&target_stat_lu_attr_lu_name,
	&target_stat_lu_attr_vend,
	&target_stat_lu_attr_prod,
	&target_stat_lu_attr_rev,
	&target_stat_lu_attr_dev_type,
	&target_stat_lu_attr_status,
	&target_stat_lu_attr_state_bit,
	&target_stat_lu_attr_num_cmds,
	&target_stat_lu_attr_read_mbytes,
	&target_stat_lu_attr_write_mbytes,
	&target_stat_lu_attr_resets,
	&target_stat_lu_attr_full_stat,
	&target_stat_lu_attr_hs_num_cmds,
	&target_stat_lu_attr_creation_time,
	NULL,
};

static struct config_item_type target_stat_scsi_lu_cit = {
	.ct_attrs		= target_stat_scsi_lu_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * Called from target_core_configfs.c:target_core_make_subdev() to setup
 * the target statistics groups + configfs CITs located in target_core_stat.c
 */
void target_stat_setup_dev_default_groups(struct se_device *dev)
{
	config_group_init_type_name(&dev->dev_stat_grps.scsi_dev_group,
			"scsi_dev", &target_stat_scsi_dev_cit);
	configfs_add_default_group(&dev->dev_stat_grps.scsi_dev_group,
			&dev->dev_stat_grps.stat_group);

	config_group_init_type_name(&dev->dev_stat_grps.scsi_tgt_dev_group,
			"scsi_tgt_dev", &target_stat_scsi_tgt_dev_cit);
	configfs_add_default_group(&dev->dev_stat_grps.scsi_tgt_dev_group,
			&dev->dev_stat_grps.stat_group);

	config_group_init_type_name(&dev->dev_stat_grps.scsi_lu_group,
			"scsi_lu", &target_stat_scsi_lu_cit);
	configfs_add_default_group(&dev->dev_stat_grps.scsi_lu_group,
			&dev->dev_stat_grps.stat_group);
}

/*
 * SCSI Port Table
 */

static struct se_lun *to_stat_port(struct config_item *item)
{
	struct se_port_stat_grps *pgrps = container_of(to_config_group(item),
			struct se_port_stat_grps, scsi_port_group);
	return container_of(pgrps, struct se_lun, port_stat_grps);
}

static ssize_t target_stat_port_inst_show(struct config_item *item, char *page)
{
	struct se_lun *lun = to_stat_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n", dev->hba_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_port_dev_show(struct config_item *item, char *page)
{
	struct se_lun *lun = to_stat_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n", dev->dev_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_port_indx_show(struct config_item *item, char *page)
{
	struct se_lun *lun = to_stat_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n", lun->lun_rtpi);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_port_role_show(struct config_item *item, char *page)
{
	struct se_lun *lun = to_stat_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%s%u\n", "Device", dev->dev_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_port_busy_count_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev) {
		/* FIXME: scsiPortBusyStatuses  */
		ret = snprintf(page, PAGE_SIZE, "%u\n", 0);
	}
	rcu_read_unlock();
	return ret;
}

CONFIGFS_ATTR_RO(target_stat_port_, inst);
CONFIGFS_ATTR_RO(target_stat_port_, dev);
CONFIGFS_ATTR_RO(target_stat_port_, indx);
CONFIGFS_ATTR_RO(target_stat_port_, role);
CONFIGFS_ATTR_RO(target_stat_port_, busy_count);

static struct configfs_attribute *target_stat_scsi_port_attrs[] = {
	&target_stat_port_attr_inst,
	&target_stat_port_attr_dev,
	&target_stat_port_attr_indx,
	&target_stat_port_attr_role,
	&target_stat_port_attr_busy_count,
	NULL,
};

static struct config_item_type target_stat_scsi_port_cit = {
	.ct_attrs		= target_stat_scsi_port_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * SCSI Target Port Table
 */
static struct se_lun *to_stat_tgt_port(struct config_item *item)
{
	struct se_port_stat_grps *pgrps = container_of(to_config_group(item),
			struct se_port_stat_grps, scsi_tgt_port_group);
	return container_of(pgrps, struct se_lun, port_stat_grps);
}

#define DEV_STAT_TGT_PORT_SHOW_HIST(_name)				\
static ssize_t target_stat_tgt_port_##_name##_show(			\
	struct config_item *item, char *page)				\
{									\
	ssize_t size = -ENODEV;						\
	struct se_device *dev;						\
	struct se_lun *lun = to_stat_port(item);			\
									\
	rcu_read_lock();						\
	dev = rcu_dereference(lun->lun_se_dev);				\
	if (dev) {							\
		size = snprintf_histogram(page, PAGE_SIZE,		\
			rcu_dereference(lun->lun_stats._name));		\
	}								\
	rcu_read_unlock();						\
	return size;							\
}

#define DEV_STAT_TGT_PORT_STORE_HIST(_name)				\
static ssize_t target_stat_tgt_port_##_name##_store(			\
	struct config_item *item, const char *page, size_t size)	\
{									\
	struct se_device *dev;						\
	struct se_lun *lun = to_stat_port(item);			\
	struct scsi_port_stats_hist *old, *new;				\
	ssize_t ret;							\
									\
	new = kzalloc(sizeof(*new), GFP_KERNEL);			\
	if (!new)							\
		return -ENOMEM;						\
									\
	ret = read_histogram_items(page,				\
		size, new->items, TCM_SE_PORT_STATS_HIST_MAX - 1);	\
									\
	if (ret < 0)							\
		goto err;						\
									\
	if (ret == 0) {							\
		kfree(new);						\
		new = NULL;						\
	} else	{							\
		new->items[ret] = U64_MAX;				\
		new->count = ret + 1;					\
	}								\
									\
	rcu_read_lock();						\
	dev = rcu_dereference(lun->lun_se_dev);				\
									\
	if (!dev) {							\
		rcu_read_unlock();					\
		ret = -ENODEV;						\
		goto err;						\
	}								\
									\
	old = rcu_dereference(lun->lun_stats._name);			\
	rcu_assign_pointer(lun->lun_stats._name, new);			\
									\
	rcu_read_unlock();						\
									\
	if (old)							\
		kfree_rcu(old, rcu_head);				\
									\
	return size;							\
									\
err:									\
	if (new)							\
		kfree(new);						\
	return ret;							\
}

static void scsi_port_stats_hist_observe_bsearch(
		struct scsi_port_stats_hist *hist, u64 val)
{
	size_t start = 0, end = hist->count - 1;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		if (val < hist->items[mid])
			end = mid;
		else
			start = mid + 1;
	}

	atomic64_inc(&hist->counters[start]);
}

void scsi_port_stats_hist_observe(
		struct scsi_port_stats_hist *hist, u64 val)
{
	if (!hist)
		return;

	scsi_port_stats_hist_observe_bsearch(hist, val);
}

static ssize_t find_token(const char *page, size_t size,
		size_t offset, size_t *token_len)
{
	size_t i;
	ssize_t pos = -1;
	size_t len = 0;

	BUG_ON(offset > size);

	for (i = offset; i < size; ++i) {
		if (isspace(page[i])) {
			if (len)
				break;
		} else if (!len++) {
			pos = i;
		}
	}

	if (pos > -1)
		*token_len = len;

	return pos;
}

static ssize_t read_histogram_items(const char *page, size_t size,
		u64 *items, u8 items_max)
{
	u8 total = 0;
	size_t token_len = 0;
	ssize_t pos;

	if (size == 0)
		return 0;

	pos = find_token(page, size, 0, &token_len);
	if (pos == -1)
		return 0;

	while (pos != -1) {
		int ret;
		char buf[64];
		u64 item;

		if (token_len >= sizeof(buf))
			return -EINVAL;

		if (total == items_max) {
			pr_err("items count can't be greater than %d: %d",
					items_max, -EPERM);
			return -EINVAL;
		}

		memcpy(buf, page + pos, token_len);
		buf[token_len] = 0;

		ret = kstrtou64(buf, 10, &item);
		if (ret < 0) {
			pr_err("kstrtou64() failed for an item '%s': %d",
					buf, ret);
			return ret;
		}

		if ((item <= 0) || (total && item <= items[total - 1])) {
			pr_err("items must be positive, unique and sorted: %d",
					-EINVAL);
			return -EINVAL;
		}

		items[total++] = item;
		pos = find_token(page, size, pos + token_len, &token_len);
	}

	return total;
}

static ssize_t snprintf_histogram(char *page, size_t size,
		struct scsi_port_stats_hist *hist)
{
	ssize_t ret = 0;
	u8 i;

	if (!hist)
		return 0;

	for (i = 0; i < hist->count - 1; ++i)
		ret += snprintf(page + ret, PAGE_SIZE - ret,
			"%llu ", (u64)atomic64_read(&hist->counters[i]));

	ret += snprintf(page + ret, PAGE_SIZE - ret,
		"%llu\n", (u64)atomic64_read(&hist->counters[i]));

	return ret;
}

DEV_STAT_TGT_PORT_STORE_HIST(read_hist);
DEV_STAT_TGT_PORT_SHOW_HIST(read_hist);
CONFIGFS_ATTR(target_stat_tgt_port_, read_hist);

DEV_STAT_TGT_PORT_STORE_HIST(write_hist);
DEV_STAT_TGT_PORT_SHOW_HIST(write_hist);
CONFIGFS_ATTR(target_stat_tgt_port_, write_hist);

DEV_STAT_TGT_PORT_STORE_HIST(sync_hist);
DEV_STAT_TGT_PORT_SHOW_HIST(sync_hist);
CONFIGFS_ATTR(target_stat_tgt_port_, sync_hist);

static ssize_t target_stat_tgt_port_inst_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_tgt_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n", dev->hba_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_tgt_port_dev_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_tgt_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n", dev->dev_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_tgt_port_indx_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_tgt_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n", lun->lun_rtpi);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_tgt_port_name_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_tgt_port(item);
	struct se_portal_group *tpg = lun->lun_tpg;
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%sPort#%u\n",
			tpg->se_tpg_tfo->fabric_name,
			lun->lun_rtpi);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_tgt_port_port_index_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_tgt_port(item);
	struct se_portal_group *tpg = lun->lun_tpg;
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%s%s%d\n",
			tpg->se_tpg_tfo->tpg_get_wwn(tpg), "+t+",
			tpg->se_tpg_tfo->tpg_get_tag(tpg));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_tgt_port_in_cmds_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_tgt_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%lu\n",
			       atomic_long_read(&lun->lun_stats.cmd_pdus));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_tgt_port_write_mbytes_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_tgt_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n",
			(u32)(atomic_long_read(&lun->lun_stats.rx_data_octets) >> 20));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_tgt_port_read_mbytes_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_tgt_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n",
				(u32)(atomic_long_read(&lun->lun_stats.tx_data_octets) >> 20));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_tgt_port_hs_in_cmds_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_stat_tgt_port(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev) {
		/* FIXME: scsiTgtPortHsInCommands */
		ret = snprintf(page, PAGE_SIZE, "%u\n", 0);
	}
	rcu_read_unlock();
	return ret;
}

#define DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(_name, _value)		\
static ssize_t  target_stat_tgt_port_##_name##_show(			\
	struct config_item *item, char *page)				\
{									\
	struct se_lun *lun = to_stat_port(item);			\
	struct se_device *dev;						\
	ssize_t ret = -ENODEV;						\
									\
	rcu_read_lock();						\
	dev = rcu_dereference(lun->lun_se_dev);				\
	if (dev) {							\
		ret = snprintf(page, PAGE_SIZE, "%lu\n",		\
			atomic_long_read(&lun->lun_stats._value));	\
	}								\
	rcu_read_unlock();						\
	return ret;							\
}

DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(read_bytes, tx_data_octets);
DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(write_bytes, rx_data_octets);
DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(read_cmds, read_cmds);
DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(write_cmds, write_cmds);
DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(bidi_cmds, bidi_cmds);
DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(read_errors, read_errors);
DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(write_errors, write_errors);
DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(bidi_errors, bidi_errors);
DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(aborts, aborts);
DEV_STAT_TGT_PORT_STATS_SHOW_SIMPLE(queue_cmds, queue_cmds);

CONFIGFS_ATTR_RO(target_stat_tgt_port_, inst);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, dev);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, indx);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, name);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, port_index);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, in_cmds);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, write_mbytes);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, read_mbytes);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, hs_in_cmds);

CONFIGFS_ATTR_RO(target_stat_tgt_port_, read_bytes);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, write_bytes);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, read_cmds);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, write_cmds);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, bidi_cmds);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, read_errors);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, write_errors);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, bidi_errors);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, aborts);
CONFIGFS_ATTR_RO(target_stat_tgt_port_, queue_cmds);

static struct configfs_attribute *target_stat_scsi_tgt_port_attrs[] = {
	&target_stat_tgt_port_attr_inst,
	&target_stat_tgt_port_attr_dev,
	&target_stat_tgt_port_attr_indx,
	&target_stat_tgt_port_attr_name,
	&target_stat_tgt_port_attr_port_index,
	&target_stat_tgt_port_attr_in_cmds,
	&target_stat_tgt_port_attr_write_mbytes,
	&target_stat_tgt_port_attr_read_mbytes,
	&target_stat_tgt_port_attr_hs_in_cmds,

	&target_stat_tgt_port_attr_read_bytes,
	&target_stat_tgt_port_attr_write_bytes,
	&target_stat_tgt_port_attr_read_cmds,
	&target_stat_tgt_port_attr_write_cmds,
	&target_stat_tgt_port_attr_bidi_cmds,
	&target_stat_tgt_port_attr_read_errors,
	&target_stat_tgt_port_attr_write_errors,
	&target_stat_tgt_port_attr_bidi_errors,
	&target_stat_tgt_port_attr_aborts,
	&target_stat_tgt_port_attr_queue_cmds,
	&target_stat_tgt_port_attr_read_hist,
	&target_stat_tgt_port_attr_write_hist,
	&target_stat_tgt_port_attr_sync_hist,
	NULL,
};

static struct config_item_type target_stat_scsi_tgt_port_cit = {
	.ct_attrs		= target_stat_scsi_tgt_port_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * SCSI Transport Table
 */
static struct se_lun *to_transport_stat(struct config_item *item)
{
	struct se_port_stat_grps *pgrps = container_of(to_config_group(item),
			struct se_port_stat_grps, scsi_transport_group);
	return container_of(pgrps, struct se_lun, port_stat_grps);
}

static ssize_t target_stat_transport_inst_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_transport_stat(item);
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n", dev->hba_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_transport_device_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_transport_stat(item);
	struct se_device *dev;
	struct se_portal_group *tpg = lun->lun_tpg;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev) {
		/* scsiTransportType */
		ret = snprintf(page, PAGE_SIZE, "scsiTransport%s\n",
			       tpg->se_tpg_tfo->fabric_name);
	}
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_transport_indx_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_transport_stat(item);
	struct se_device *dev;
	struct se_portal_group *tpg = lun->lun_tpg;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n",
			       tpg->se_tpg_tfo->tpg_get_inst_index(tpg));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_transport_dev_name_show(struct config_item *item,
		char *page)
{
	struct se_lun *lun = to_transport_stat(item);
	struct se_device *dev;
	struct se_portal_group *tpg = lun->lun_tpg;
	struct t10_wwn *wwn;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev) {
		wwn = &dev->t10_wwn;
		/* scsiTransportDevName */
		ret = snprintf(page, PAGE_SIZE, "%s+%s\n",
				tpg->se_tpg_tfo->tpg_get_wwn(tpg),
				(strlen(wwn->unit_serial)) ? wwn->unit_serial :
				wwn->vendor);
	}
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_transport_proto_id_show(struct config_item *item, char *page)
{
	struct se_lun *lun = to_transport_stat(item);
	struct se_portal_group *tpg = lun->lun_tpg;
	struct se_device *dev;
	ssize_t ret = -ENODEV;

	rcu_read_lock();
	dev = rcu_dereference(lun->lun_se_dev);
	if (dev)
		ret = snprintf(page, PAGE_SIZE, "%u\n", tpg->proto_id);
	rcu_read_unlock();
	return ret;
}

CONFIGFS_ATTR_RO(target_stat_transport_, inst);
CONFIGFS_ATTR_RO(target_stat_transport_, device);
CONFIGFS_ATTR_RO(target_stat_transport_, indx);
CONFIGFS_ATTR_RO(target_stat_transport_, dev_name);
CONFIGFS_ATTR_RO(target_stat_transport_, proto_id);

static struct configfs_attribute *target_stat_scsi_transport_attrs[] = {
	&target_stat_transport_attr_inst,
	&target_stat_transport_attr_device,
	&target_stat_transport_attr_indx,
	&target_stat_transport_attr_dev_name,
	&target_stat_transport_attr_proto_id,
	NULL,
};

static struct config_item_type target_stat_scsi_transport_cit = {
	.ct_attrs		= target_stat_scsi_transport_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * Called from target_core_fabric_configfs.c:target_fabric_make_lun() to setup
 * the target port statistics groups + configfs CITs located in target_core_stat.c
 */
void target_stat_setup_port_default_groups(struct se_lun *lun)
{
	config_group_init_type_name(&lun->port_stat_grps.scsi_port_group,
			"scsi_port", &target_stat_scsi_port_cit);
	configfs_add_default_group(&lun->port_stat_grps.scsi_port_group,
			&lun->port_stat_grps.stat_group);

	config_group_init_type_name(&lun->port_stat_grps.scsi_tgt_port_group,
			"scsi_tgt_port", &target_stat_scsi_tgt_port_cit);
	configfs_add_default_group(&lun->port_stat_grps.scsi_tgt_port_group,
			&lun->port_stat_grps.stat_group);

	config_group_init_type_name(&lun->port_stat_grps.scsi_transport_group,
			"scsi_transport", &target_stat_scsi_transport_cit);
	configfs_add_default_group(&lun->port_stat_grps.scsi_transport_group,
			&lun->port_stat_grps.stat_group);
}

/*
 * SCSI Authorized Initiator Table
 */

static struct se_lun_acl *auth_to_lacl(struct config_item *item)
{
	struct se_ml_stat_grps *lgrps = container_of(to_config_group(item),
			struct se_ml_stat_grps, scsi_auth_intr_group);
	return container_of(lgrps, struct se_lun_acl, ml_stat_grps);
}

static ssize_t target_stat_auth_inst_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	struct se_portal_group *tpg;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	tpg = nacl->se_tpg;
	/* scsiInstIndex */
	ret = snprintf(page, PAGE_SIZE, "%u\n",
			tpg->se_tpg_tfo->tpg_get_inst_index(tpg));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_dev_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	struct se_lun *lun;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	lun = rcu_dereference(deve->se_lun);
	/* scsiDeviceIndex */
	ret = snprintf(page, PAGE_SIZE, "%u\n", lun->lun_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_port_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	struct se_portal_group *tpg;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	tpg = nacl->se_tpg;
	/* scsiAuthIntrTgtPortIndex */
	ret = snprintf(page, PAGE_SIZE, "%u\n", tpg->se_tpg_tfo->tpg_get_tag(tpg));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_indx_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* scsiAuthIntrIndex */
	ret = snprintf(page, PAGE_SIZE, "%u\n", nacl->acl_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_dev_or_port_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* scsiAuthIntrDevOrPort */
	ret = snprintf(page, PAGE_SIZE, "%u\n", 1);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_intr_name_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* scsiAuthIntrName */
	ret = snprintf(page, PAGE_SIZE, "%s\n", nacl->initiatorname);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_map_indx_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* FIXME: scsiAuthIntrLunMapIndex */
	ret = snprintf(page, PAGE_SIZE, "%u\n", 0);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_att_count_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* scsiAuthIntrAttachedTimes */
	ret = snprintf(page, PAGE_SIZE, "%u\n", deve->attach_count);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_num_cmds_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* scsiAuthIntrOutCommands */
	ret = snprintf(page, PAGE_SIZE, "%lu\n",
		       atomic_long_read(&deve->total_cmds));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_read_mbytes_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* scsiAuthIntrReadMegaBytes */
	ret = snprintf(page, PAGE_SIZE, "%u\n",
		      (u32)(atomic_long_read(&deve->read_bytes) >> 20));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_write_mbytes_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* scsiAuthIntrWrittenMegaBytes */
	ret = snprintf(page, PAGE_SIZE, "%u\n",
		      (u32)(atomic_long_read(&deve->write_bytes) >> 20));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_hs_num_cmds_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* FIXME: scsiAuthIntrHSOutCommands */
	ret = snprintf(page, PAGE_SIZE, "%u\n", 0);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_creation_time_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* scsiAuthIntrLastCreation */
	ret = snprintf(page, PAGE_SIZE, "%u\n", (u32)(((u32)deve->creation_time -
				INITIAL_JIFFIES) * 100 / HZ));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_auth_row_status_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = auth_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* FIXME: scsiAuthIntrRowStatus */
	ret = snprintf(page, PAGE_SIZE, "Ready\n");
	rcu_read_unlock();
	return ret;
}

CONFIGFS_ATTR_RO(target_stat_auth_, inst);
CONFIGFS_ATTR_RO(target_stat_auth_, dev);
CONFIGFS_ATTR_RO(target_stat_auth_, port);
CONFIGFS_ATTR_RO(target_stat_auth_, indx);
CONFIGFS_ATTR_RO(target_stat_auth_, dev_or_port);
CONFIGFS_ATTR_RO(target_stat_auth_, intr_name);
CONFIGFS_ATTR_RO(target_stat_auth_, map_indx);
CONFIGFS_ATTR_RO(target_stat_auth_, att_count);
CONFIGFS_ATTR_RO(target_stat_auth_, num_cmds);
CONFIGFS_ATTR_RO(target_stat_auth_, read_mbytes);
CONFIGFS_ATTR_RO(target_stat_auth_, write_mbytes);
CONFIGFS_ATTR_RO(target_stat_auth_, hs_num_cmds);
CONFIGFS_ATTR_RO(target_stat_auth_, creation_time);
CONFIGFS_ATTR_RO(target_stat_auth_, row_status);

static struct configfs_attribute *target_stat_scsi_auth_intr_attrs[] = {
	&target_stat_auth_attr_inst,
	&target_stat_auth_attr_dev,
	&target_stat_auth_attr_port,
	&target_stat_auth_attr_indx,
	&target_stat_auth_attr_dev_or_port,
	&target_stat_auth_attr_intr_name,
	&target_stat_auth_attr_map_indx,
	&target_stat_auth_attr_att_count,
	&target_stat_auth_attr_num_cmds,
	&target_stat_auth_attr_read_mbytes,
	&target_stat_auth_attr_write_mbytes,
	&target_stat_auth_attr_hs_num_cmds,
	&target_stat_auth_attr_creation_time,
	&target_stat_auth_attr_row_status,
	NULL,
};

static struct config_item_type target_stat_scsi_auth_intr_cit = {
	.ct_attrs		= target_stat_scsi_auth_intr_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * SCSI Attached Initiator Port Table
 */

static struct se_lun_acl *iport_to_lacl(struct config_item *item)
{
	struct se_ml_stat_grps *lgrps = container_of(to_config_group(item),
			struct se_ml_stat_grps, scsi_att_intr_port_group);
	return container_of(lgrps, struct se_lun_acl, ml_stat_grps);
}

static ssize_t target_stat_iport_inst_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = iport_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	struct se_portal_group *tpg;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	tpg = nacl->se_tpg;
	/* scsiInstIndex */
	ret = snprintf(page, PAGE_SIZE, "%u\n",
			tpg->se_tpg_tfo->tpg_get_inst_index(tpg));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_iport_dev_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = iport_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	struct se_lun *lun;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	lun = rcu_dereference(deve->se_lun);
	/* scsiDeviceIndex */
	ret = snprintf(page, PAGE_SIZE, "%u\n", lun->lun_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_iport_port_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = iport_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	struct se_portal_group *tpg;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	tpg = nacl->se_tpg;
	/* scsiPortIndex */
	ret = snprintf(page, PAGE_SIZE, "%u\n", tpg->se_tpg_tfo->tpg_get_tag(tpg));
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_iport_indx_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = iport_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_session *se_sess;
	struct se_portal_group *tpg;
	ssize_t ret;

	spin_lock_irq(&nacl->nacl_sess_lock);
	se_sess = nacl->nacl_sess;
	if (!se_sess) {
		spin_unlock_irq(&nacl->nacl_sess_lock);
		return -ENODEV;
	}

	tpg = nacl->se_tpg;
	/* scsiAttIntrPortIndex */
	ret = snprintf(page, PAGE_SIZE, "%u\n",
			tpg->se_tpg_tfo->sess_get_index(se_sess));
	spin_unlock_irq(&nacl->nacl_sess_lock);
	return ret;
}

static ssize_t target_stat_iport_port_auth_indx_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = iport_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_dev_entry *deve;
	ssize_t ret;

	rcu_read_lock();
	deve = target_nacl_find_deve(nacl, lacl->mapped_lun);
	if (!deve) {
		rcu_read_unlock();
		return -ENODEV;
	}
	/* scsiAttIntrPortAuthIntrIdx */
	ret = snprintf(page, PAGE_SIZE, "%u\n", nacl->acl_index);
	rcu_read_unlock();
	return ret;
}

static ssize_t target_stat_iport_port_ident_show(struct config_item *item,
		char *page)
{
	struct se_lun_acl *lacl = iport_to_lacl(item);
	struct se_node_acl *nacl = lacl->se_lun_nacl;
	struct se_session *se_sess;
	struct se_portal_group *tpg;
	ssize_t ret;
	unsigned char buf[64];

	spin_lock_irq(&nacl->nacl_sess_lock);
	se_sess = nacl->nacl_sess;
	if (!se_sess) {
		spin_unlock_irq(&nacl->nacl_sess_lock);
		return -ENODEV;
	}

	tpg = nacl->se_tpg;
	/* scsiAttIntrPortName+scsiAttIntrPortIdentifier */
	memset(buf, 0, 64);
	if (tpg->se_tpg_tfo->sess_get_initiator_sid != NULL)
		tpg->se_tpg_tfo->sess_get_initiator_sid(se_sess, buf, 64);

	ret = snprintf(page, PAGE_SIZE, "%s+i+%s\n", nacl->initiatorname, buf);
	spin_unlock_irq(&nacl->nacl_sess_lock);
	return ret;
}

CONFIGFS_ATTR_RO(target_stat_iport_, inst);
CONFIGFS_ATTR_RO(target_stat_iport_, dev);
CONFIGFS_ATTR_RO(target_stat_iport_, port);
CONFIGFS_ATTR_RO(target_stat_iport_, indx);
CONFIGFS_ATTR_RO(target_stat_iport_, port_auth_indx);
CONFIGFS_ATTR_RO(target_stat_iport_, port_ident);

static struct configfs_attribute *target_stat_scsi_ath_intr_port_attrs[] = {
	&target_stat_iport_attr_inst,
	&target_stat_iport_attr_dev,
	&target_stat_iport_attr_port,
	&target_stat_iport_attr_indx,
	&target_stat_iport_attr_port_auth_indx,
	&target_stat_iport_attr_port_ident,
	NULL,
};

static struct config_item_type target_stat_scsi_att_intr_port_cit = {
	.ct_attrs		= target_stat_scsi_ath_intr_port_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * Called from target_core_fabric_configfs.c:target_fabric_make_mappedlun() to setup
 * the target MappedLUN statistics groups + configfs CITs located in target_core_stat.c
 */
void target_stat_setup_mappedlun_default_groups(struct se_lun_acl *lacl)
{
	config_group_init_type_name(&lacl->ml_stat_grps.scsi_auth_intr_group,
			"scsi_auth_intr", &target_stat_scsi_auth_intr_cit);
	configfs_add_default_group(&lacl->ml_stat_grps.scsi_auth_intr_group,
			&lacl->ml_stat_grps.stat_group);

	config_group_init_type_name(&lacl->ml_stat_grps.scsi_att_intr_port_group,
			"scsi_att_intr_port", &target_stat_scsi_att_intr_port_cit);
	configfs_add_default_group(&lacl->ml_stat_grps.scsi_att_intr_port_group,
			&lacl->ml_stat_grps.stat_group);
}
