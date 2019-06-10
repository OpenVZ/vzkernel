/*
 *  drivers/block/ploop/io.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>

#include <linux/ploop/ploop.h>
#include <linux/ploop/ploop_if.h>
#include "ploop_events.h"

/* Generic IO routines. */

static LIST_HEAD(ploop_ios);
static DEFINE_MUTEX(ploop_ios_mutex);

int ploop_register_io(struct ploop_io_ops * ops)
{
	mutex_lock(&ploop_ios_mutex);
	list_add(&ops->list, &ploop_ios);
	mutex_unlock(&ploop_ios_mutex);
	return 0;
}
EXPORT_SYMBOL(ploop_register_io);

void ploop_unregister_io(struct ploop_io_ops * ops)
{
	mutex_lock(&ploop_ios_mutex);
	list_del(&ops->list);
	mutex_unlock(&ploop_ios_mutex);
}
EXPORT_SYMBOL(ploop_unregister_io);

static struct ploop_io_ops * ploop_io_get(struct ploop_io *io, unsigned int id)
{
	struct ploop_io_ops * ops;

	mutex_lock(&ploop_ios_mutex);
	list_for_each_entry(ops, &ploop_ios, list) {
		if ((id == ops->id || id == PLOOP_IO_AUTO) &&
		    !ops->autodetect(io) && try_module_get(ops->owner)) {
			mutex_unlock(&ploop_ios_mutex);
			return ops;
		}
	}
	mutex_unlock(&ploop_ios_mutex);
	return NULL;
}

void ploop_io_put(struct ploop_io_ops * ops)
{
	module_put(ops->owner);
}


int
ploop_io_init(struct ploop_delta * delta, int nchunks, struct ploop_ctl_chunk * pc)
{
	int err;

	if (nchunks != 1)
		return -EINVAL;

	if (pc[0].pctl_offset ||
	    pc[0].pctl_start ||
	    pc[0].pctl_len)
		return -EINVAL;

	memset(&delta->io, 0, sizeof(struct ploop_io));
	delta->io.plo = delta->plo;
	delta->io.n_chunks = 1;

	err = -EBADF;
	delta->io.files.file = fget(pc[0].pctl_fd);
	if (!delta->io.files.file)
		goto out_err;

	err = -EOPNOTSUPP;
	delta->io.ops = ploop_io_get(&delta->io, pc[0].pctl_type);
	if (delta->io.ops == NULL)
		goto out_err;

	err = delta->io.ops->init(&delta->io);
	if (err)
		goto out_err;

	return 0;

out_err:
	if (delta->io.files.file)
		fput(delta->io.files.file);
	delta->io.files.file = NULL;
	if (delta->io.ops)
		ploop_io_put(delta->io.ops);
	delta->io.ops = NULL;
	return err;
}
EXPORT_SYMBOL(ploop_io_init);

int ploop_io_open(struct ploop_io * io)
{
	struct file * file;
	struct ploop_delta * delta = container_of(io, struct ploop_delta, io);

	if ((file = io->files.file) == NULL)
		return -EBADF;

	if ((delta->flags & PLOOP_FMT_RDONLY) &&
	    (io->ops->f_mode(io) & FMODE_WRITE))
		return -EINVAL;

	if (!(delta->flags & PLOOP_FMT_RDONLY) &&
	    !(io->ops->f_mode(io) & FMODE_WRITE))
		return -EINVAL;

	return io->ops->open(io);
}
EXPORT_SYMBOL(ploop_io_open);

void ploop_io_destroy(struct ploop_io * io)
{
	if (io->ops) {
		io->ops->destroy(io);
		ploop_io_put(io->ops);
		io->ops = NULL;
	}
}
EXPORT_SYMBOL(ploop_io_destroy);

void ploop_io_report_fn(struct file * file, char * msg)
{
	char *fn = "?";
	char *path;

	path = (char *)__get_free_page(GFP_KERNEL);
	if (path) {
		fn = d_path(&file->f_path, path, PAGE_SIZE);
		if (IS_ERR(fn))
			fn = "?";
	}

	printk("%s: %s\n", msg, fn);

	if (path)
		free_page((unsigned long)path);
}
EXPORT_SYMBOL(ploop_io_report_fn);

int ploop_submit_alloc(struct ploop_delta *delta, struct ploop_request *preq,
		       struct bio_list *sbl, unsigned int size, iblock_t iblk)
{
	struct ploop_io *io = &delta->io;
	bool advanced = false;
	int ret;

	trace_submit_alloc(preq);

	if (!(io->files.file->f_mode & FMODE_WRITE) ||
	    (delta->flags & PLOOP_FMT_RDONLY)) {
		PLOOP_FAIL_REQUEST(preq, -EBADF);
		return -1;
	}

	if (!iblk)
		iblk = io->alloc_head;
	if (iblk == io->alloc_head) {
		/*
		 * Note, even if not zero iblk was passed as parameter,
		 * alloc_head also must be incremented.
		 */
		io->alloc_head++;
		advanced = true;
	}

	ret = io->ops->submit_alloc(io, preq, sbl, size, iblk);

	/* FIXME: why original code handles only ENOSPC? */
	if ((ret == 0 || ret == -ENOSPC) && advanced)
		io->alloc_head--;

	WARN_ON_ONCE(iblk > io->alloc_head);

	return ret;
}
EXPORT_SYMBOL(ploop_submit_alloc);
