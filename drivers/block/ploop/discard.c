#include <linux/module.h>
#include <linux/bio.h>

#include <linux/ploop/ploop.h>
#include "discard.h"
#include "freeblks.h"

int ploop_discard_init_ioc(struct ploop_device *plo)
{
	struct ploop_freeblks_desc *fbd;
	struct ploop_delta *delta = ploop_top_delta(plo);

	if (delta == NULL)
		return -EINVAL;

	if (delta->ops->id != PLOOP_FMT_PLOOP1)
		return -EOPNOTSUPP;

	if (plo->maintenance_type != PLOOP_MNTN_OFF)
		return -EBUSY;

	fbd = ploop_fb_init(plo);
	if (!fbd)
		return -ENOMEM;

	ploop_quiesce(plo);

	ploop_fb_set_freezed_level(fbd, delta->level);

	plo->fbd = fbd;

	atomic_set(&plo->maintenance_cnt, 0);
	init_completion(&plo->maintenance_comp);
	plo->maintenance_type = PLOOP_MNTN_DISCARD;
	set_bit(PLOOP_S_DISCARD, &plo->state);

	ploop_relax(plo);

	return 0;
}

int ploop_discard_fini_ioc(struct ploop_device *plo)
{
	int ret = 0;
	struct ploop_request *preq, *tmp;
	LIST_HEAD(drop_list);

	if (!test_and_clear_bit(PLOOP_S_DISCARD, &plo->state))
		return 0;

	ploop_quiesce(plo);

	spin_lock_irq(&plo->lock);
	list_for_each_entry_safe(preq, tmp, &plo->entry_queue, list)
		if (test_bit(PLOOP_REQ_DISCARD, &preq->state)) {
			list_move(&preq->list, &drop_list);
			ploop_entry_qlen_dec(preq);
		}
	spin_unlock_irq(&plo->lock);

	if (!list_empty(&drop_list))
		ploop_preq_drop(plo, &drop_list, 0);

	if (plo->maintenance_type != PLOOP_MNTN_DISCARD) {
		ret = -EBUSY;
		goto out;
	}

	ploop_fb_fini(plo->fbd, -EOPNOTSUPP);

	clear_bit(PLOOP_S_DISCARD_LOADED, &plo->state);

	plo->maintenance_type = PLOOP_MNTN_OFF;
	complete(&plo->maintenance_comp);

out:
	ploop_relax(plo);

	return ret;
}

int ploop_discard_wait_ioc(struct ploop_device *plo)
{
	int err;

	if (!test_bit(PLOOP_S_DISCARD, &plo->state))
		return 0;

	if (plo->maintenance_type == PLOOP_MNTN_FBLOADED)
		return 1;

	if (plo->maintenance_type != PLOOP_MNTN_DISCARD)
		return -EINVAL;

	err = ploop_maintenance_wait(plo);
	if (err)
		goto out;

	/* maintenance_cnt is zero without discard requests,
	 * in this case ploop_maintenance_wait returns 0
	 * instead of ERESTARTSYS */
	if (test_bit(PLOOP_S_DISCARD_LOADED, &plo->state)) {
		err = 1;
	} else if (signal_pending(current))
		err = -ERESTARTSYS;
out:
	return err;
}
