#ifndef _RAID5_LOG_H
#define _RAID5_LOG_H

extern int r5l_init_log(struct r5conf *conf, struct md_rdev *rdev);
extern void r5l_exit_log(struct r5conf *conf);
extern int r5l_write_stripe(struct r5l_log *log, struct stripe_head *head_sh);
extern void r5l_write_stripe_run(struct r5l_log *log);
extern void r5l_flush_stripe_to_raid(struct r5l_log *log);
extern void r5l_stripe_write_finished(struct stripe_head *sh);
extern int r5l_handle_flush_request(struct r5l_log *log, struct bio *bio);
extern void r5l_quiesce(struct r5l_log *log, int state);
extern bool r5l_log_disk_error(struct r5conf *conf);

extern struct dma_async_tx_descriptor *
ops_run_partial_parity(struct stripe_head *sh, struct raid5_percpu *percpu,
		       struct dma_async_tx_descriptor *tx);
extern int ppl_init_log(struct r5conf *conf);
extern void ppl_exit_log(struct r5conf *conf);
extern int ppl_write_stripe(struct r5conf *conf, struct stripe_head *sh);
extern void ppl_write_stripe_run(struct r5conf *conf);
extern void ppl_stripe_write_finished(struct stripe_head *sh);
extern int ppl_modify_log(struct r5conf *conf, struct md_rdev *rdev, bool add);

static inline bool raid5_has_ppl(struct r5conf *conf)
{
	return test_bit(MD_HAS_PPL, &conf->mddev->flags);
}

static inline int log_stripe(struct stripe_head *sh, struct stripe_head_state *s)
{
	struct r5conf *conf = sh->raid_conf;

	if (conf->log)
		return r5l_write_stripe(conf->log, sh);
	else if (raid5_has_ppl(conf))
		return ppl_write_stripe(conf, sh);

	return -EAGAIN;
}

static inline void log_stripe_write_finished(struct stripe_head *sh)
{
	struct r5conf *conf = sh->raid_conf;

	if (conf->log)
		r5l_stripe_write_finished(sh);
	else if (raid5_has_ppl(conf))
		ppl_stripe_write_finished(sh);
}

static inline void log_write_stripe_run(struct r5conf *conf)
{
	if (conf->log)
		r5l_write_stripe_run(conf->log);
	else if (raid5_has_ppl(conf))
		ppl_write_stripe_run(conf);
}

static inline void log_exit(struct r5conf *conf)
{
	if (conf->log)
		r5l_exit_log(conf);
	else if (raid5_has_ppl(conf))
		ppl_exit_log(conf);
}

static inline int log_init(struct r5conf *conf, struct md_rdev *journal_dev,
			   bool ppl)
{
	if (journal_dev)
		return r5l_init_log(conf, journal_dev);
	else if (ppl)
		return ppl_init_log(conf);

	return 0;
}

static inline int log_modify(struct r5conf *conf, struct md_rdev *rdev, bool add)
{
	if (raid5_has_ppl(conf))
		return ppl_modify_log(conf, rdev, add);

	return 0;
}

#endif
