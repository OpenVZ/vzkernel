/*
 *  drivers/block/ploop/io_kaio_map.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/ploop/ploop.h>

struct ploop_mapping
{
	struct list_head	list;
	struct address_space	* mapping;
	int			readers;
};

static LIST_HEAD(ploop_mappings);
static DEFINE_SPINLOCK(ploop_mappings_lock);

int ploop_kaio_open(struct file * file, int rdonly)
{
	int err = 0;
	struct ploop_mapping *m, *pm;
	struct address_space * mapping = file->f_mapping;

	pm = kzalloc(sizeof(struct ploop_mapping), GFP_KERNEL);

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			if (rdonly) {
				if (m->readers < 0)
					err = -ETXTBSY;
				else
					m->readers++;
			} else {
				if (m->readers)
					err = -EBUSY;
				else
					m->readers = -1;
			}
			goto kaio_open_done;
		}
	}

	if (pm == NULL) {
		err = -ENOMEM;
		goto kaio_open_done;
	}

	if (mapping->host->i_flags & S_SWAPFILE) {
		err = -EBUSY;
		goto kaio_open_done;
	}

	pm->mapping = mapping;
	pm->readers = rdonly ? 1 : -1;
	list_add(&pm->list, &ploop_mappings);
	pm = NULL;

kaio_open_done:
	spin_unlock(&ploop_mappings_lock);
	if (pm)
		kfree(pm);
	return err;
}

int ploop_kaio_close(struct address_space * mapping, int rdonly)
{
	struct ploop_mapping *m, *pm = NULL;

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			if (rdonly) {
				m->readers--;
			} else {
				BUG_ON(m->readers != -1);
				m->readers = 0;
			}

			if (m->readers == 0) {
				list_del(&m->list);
				pm = m;
			}
			break;
		}
	}
	spin_unlock(&ploop_mappings_lock);

	if (pm) {
		kfree(pm);
		return 0;
	}
	return -ENOENT;
}

void ploop_kaio_downgrade(struct address_space * mapping)
{
	struct ploop_mapping * m;

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			BUG_ON(m->readers != -1);
			m->readers = 1;
			break;
		}
	}
	spin_unlock(&ploop_mappings_lock);
}

int ploop_kaio_upgrade(struct address_space * mapping)
{
	struct ploop_mapping * m;
	int err = -ESRCH;

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			err = -EBUSY;
			if (m->readers == 1) {
				m->readers = -1;
				err = 0;
			}
			break;
		}
	}
	spin_unlock(&ploop_mappings_lock);
	return err;
}
