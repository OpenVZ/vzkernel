/* Tracker engine detects and records changed clusters.
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>

#include <linux/ploop/ploop.h>

struct track_record
{
	struct rb_node	rb_node;
	u32		start;
	u32		end;
};

static int tree_insert(struct rb_root *root, struct track_record *m)
{
	struct rb_node ** p = &root->rb_node;
	struct rb_node * parent = NULL;
	struct track_record * entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct track_record, rb_node);

		if (m->start < entry->start)
			p = &(*p)->rb_left;
		else if (m->start >= entry->end)
			p = &(*p)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&m->rb_node, parent, p);
	rb_insert_color(&m->rb_node, root);
	return 0;
}

void ploop_tracker_notify(struct ploop_device * plo, sector_t sec)
{
	struct track_record * m;

	if (!test_bit(PLOOP_S_TRACK, &plo->state))
		return;
	if (test_bit(PLOOP_S_TRACK_ABORT, &plo->state))
		return;

	sec >>= plo->cluster_log;

	m = kmalloc(sizeof(struct track_record), GFP_NOFS);
	if (m == NULL) {
		set_bit(PLOOP_S_TRACK_ABORT, &plo->state);
		return;
	}

	m->start = sec;
	m->end = sec + 1;

	spin_lock(&plo->track_lock);
	if (tree_insert(&plo->track_tree, m)) {
		kfree(m);
	} else {
		struct rb_node * rb;
		struct track_record * merge;

		if (m->start != 0) {
			rb = rb_prev(&m->rb_node);
			if (rb) {
				merge = rb_entry(rb, struct track_record, rb_node);
				if (m->start == merge->end) {
					m->start = merge->start;
					rb_erase(&merge->rb_node, &plo->track_tree);
					kfree(merge);
				}
			}
		}

		rb = rb_next(&m->rb_node);
		if (rb) {
			merge = rb_entry(rb, struct track_record, rb_node);
			if (m->end == merge->start) {
				m->end = merge->end;
				rb_erase(&merge->rb_node, &plo->track_tree);
				kfree(merge);
			}
		}
	}
	spin_unlock(&plo->track_lock);
}
EXPORT_SYMBOL(ploop_tracker_notify);

int ploop_tracker_init(struct ploop_device * plo, unsigned long arg)
{
	struct ploop_track_extent e;

	if (plo->maintenance_type != PLOOP_MNTN_OFF)
		return -EBUSY;
	if (list_empty(&plo->map.delta_list))
		return -ENOENT;

	ploop_quiesce(plo);

	e.start = 0;
	e.end = (u64)ploop_top_delta(plo)->io.alloc_head << (plo->cluster_log + 9);
	if (copy_to_user((void*)arg, &e, sizeof(struct ploop_track_extent))) {
		ploop_relax(plo);
		return -EFAULT;
	}

	set_bit(PLOOP_S_TRACK, &plo->state);
	plo->maintenance_type = PLOOP_MNTN_TRACK;
	plo->track_end = 0;
	plo->track_ptr = 0;
	ploop_relax(plo);
	return 0;
}

int ploop_tracker_setpos(struct ploop_device * plo, unsigned long arg)
{
	u64 pos;

	if (copy_from_user(&pos, (void*)arg, sizeof(u64)))
		return -EFAULT;

	if (!test_bit(PLOOP_S_TRACK, &plo->state))
		return -EINVAL;

	pos >>= 9;

	if (pos < plo->track_end) {
		/* _XXX_ This would be good to trim tail of track tree
		 * and to rewind tracking. We implement this if it will
		 * be really useful.
		 */
		if (pos)
			return -EINVAL;

		ploop_quiesce(plo);

		clear_bit(PLOOP_S_TRACK_ABORT, &plo->state);
		ploop_tracker_destroy(plo, 1);

		plo->track_end = pos;
		plo->track_ptr = 0;

		ploop_relax(plo);
	} else 
		plo->track_end = pos;

	return 0;
}

static struct track_record * find_record(struct rb_root * root, u32 start)
{
	struct rb_node * n = root->rb_node;
	struct rb_node * prev = NULL;

	while (n) {
		struct track_record * m;

		m = rb_entry(n, struct track_record, rb_node);
		prev = n;

		if (start < m->start)
			n = n->rb_left;
		else if (start >= m->end)
			n = n->rb_right;
		else
			return m;
	}

	while (prev && start >= rb_entry(prev, struct track_record, rb_node)->end)
		prev = rb_next(prev);

	if (!prev)
		return NULL;

	return rb_entry(prev, struct track_record, rb_node);
}


int ploop_tracker_read(struct ploop_device * plo, unsigned long arg)
{
	u64 ptr;
	struct track_record * m;
	struct ploop_delta * delta;
	struct ploop_track_extent e;
	int err;

	if (copy_from_user(&ptr, (void*)arg, sizeof(u64)))
		return -EFAULT;

	if (!test_bit(PLOOP_S_TRACK, &plo->state))
		return -EINVAL;

	if (test_bit(PLOOP_S_TRACK_ABORT, &plo->state)) {
		ploop_tracker_destroy(plo, 1);
		return -ECONNABORTED;
	}

	delta = ploop_top_delta(plo);

	spin_lock(&plo->track_lock);
	m = find_record(&plo->track_tree, plo->track_ptr);
	if (m == NULL) {
		if (plo->track_end >= ((sector_t)delta->io.alloc_head << plo->cluster_log) &&
		    plo->track_ptr)
			m = find_record(&plo->track_tree, 0);
	}

	if (m) {
		rb_erase(&m->rb_node, &plo->track_tree);
		plo->track_ptr = m->end;
	} else {
		plo->track_ptr = 0;
	}
	spin_unlock(&plo->track_lock);

	err = -EAGAIN;
	if (m) {
		e.start = (u64)m->start << (plo->cluster_log + 9);
		e.end = (u64)m->end << (plo->cluster_log + 9);
		kfree(m);
		err = 0;
	} else if (plo->track_end < ((sector_t)delta->io.alloc_head << plo->cluster_log)) {
		e.start = (u64)plo->track_end << 9;
		e.end = (u64)delta->io.alloc_head << (plo->cluster_log + 9);
		err = 0;
	}

	if (!err && copy_to_user((void *)arg, &e, sizeof(e))) {
		set_bit(PLOOP_S_TRACK_ABORT, &plo->state);
		err = -EFAULT;
	}

	return err;
}

int ploop_tracker_stop(struct ploop_device * plo, int force)
{
	int err;

	if (!test_bit(PLOOP_S_TRACK, &plo->state))
		return 0;

	ploop_quiesce(plo);
	if (test_bit(PLOOP_S_TRACK_ABORT, &plo->state))
		force = 1;
	err = ploop_tracker_destroy(plo, force);
	if (!err) {
		clear_bit(PLOOP_S_TRACK, &plo->state);
		plo->maintenance_type = PLOOP_MNTN_OFF;
	}
	ploop_relax(plo);
	if (test_bit(PLOOP_S_TRACK_ABORT, &plo->state))
		return -ECONNABORTED;
	return err;
}

int ploop_tracker_destroy(struct ploop_device *plo, int force)
{
	struct rb_node * n;

	if (RB_EMPTY_ROOT(&plo->track_tree))
		return 0;

	if (!force)
		return -EBUSY;

	spin_lock(&plo->track_lock);
	while ((n = rb_first(&plo->track_tree)) != NULL) {
		rb_erase(n, &plo->track_tree);
		kfree(n);
	}
	spin_unlock(&plo->track_lock);
	return 0;
}

void track_init(struct ploop_device * plo)
{
	plo->track_tree = RB_ROOT;
	spin_lock_init(&plo->track_lock);
}
