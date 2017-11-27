#include <linux/module.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/seq_file.h>
#include <linux/ctype.h>
#include <linux/oom.h>
#include <linux/ve.h>

#include <bc/beancounter.h>

static LIST_HEAD(oom_group_list_head);
static DEFINE_RWLOCK(oom_group_lock);

struct oom_group_pattern {
	char comm[TASK_COMM_LEN], pcomm[TASK_COMM_LEN];
	int oom_uid;
	int oom_score_adj;
	struct list_head group_list;
};

static void oom_groups_append(struct list_head *list)
{
	write_lock_irq(&oom_group_lock);
	list_splice_tail(list, &oom_group_list_head);
	write_unlock_irq(&oom_group_lock);
}

static void oom_groups_reset(void)
{
	struct list_head list;
	struct oom_group_pattern *gp, *tmp;

	write_lock_irq(&oom_group_lock);
	list_replace_init(&oom_group_list_head, &list);
	write_unlock_irq(&oom_group_lock);

	list_for_each_entry_safe(gp, tmp, &list, group_list)
		kfree(gp);
}

/*
 * If mask ends with asterisk it matches any comm suffix:
 * "foo" matches only "foo", "foo*" matches "foo" and "foobar"
 * "*" matches any string.
 */
static bool oom_match_comm(const char *comm, const char *mask)
{
	while (*comm && *mask != '*' && *comm == *mask) {
		comm++;
		mask++;
	}
	return (!*mask && !*comm) || (*mask == '*');
}

int get_task_oom_score_adj(struct task_struct *t)
{
	struct oom_group_pattern *gp;
	unsigned long flags;
	const struct cred *cred;
	uid_t task_uid;
	int adj = t->signal->oom_score_adj;

	/* Do not impose grouping rules if the score is adjusted by the user */
	if (adj != 0)
		return adj;

	rcu_read_lock();
	cred = __task_cred(t);
	task_uid = from_kuid_munged(cred->user_ns, cred->uid);
	rcu_read_unlock();

	read_lock_irqsave(&oom_group_lock, flags);
	list_for_each_entry(gp, &oom_group_list_head, group_list) {
		if (gp->oom_uid >= 0 && task_uid != gp->oom_uid)
			continue;
		if (gp->oom_uid < -1 && task_uid >= -gp->oom_uid)
			continue;
		if (!oom_match_comm(t->comm, gp->comm))
			continue;
		if (!oom_match_comm(t->parent->comm, gp->pcomm))
			continue;
		adj = gp->oom_score_adj;
		break;
	}
	read_unlock_irqrestore(&oom_group_lock, flags);
	return adj;
}

static int oom_group_parse_line(struct list_head *list, char *line)
{
	struct oom_group_pattern *gp;
	char dummy;
	int ret;

	gp = kmalloc(sizeof(struct oom_group_pattern), GFP_KERNEL);
	if (gp == NULL)
		return -ENOMEM;

	BUILD_BUG_ON(TASK_COMM_LEN != 16);
	ret = sscanf(line, "%15s %15s %d %d %c",
			gp->comm, gp->pcomm, &gp->oom_uid,
			&gp->oom_score_adj, &dummy);

	if (ret != 4 || gp->oom_score_adj < OOM_SCORE_ADJ_MIN ||
			gp->oom_score_adj > OOM_SCORE_ADJ_MAX) {
		kfree(gp);
		return -EINVAL;
	}

	list_add_tail(&gp->group_list, list);

	return 0;
}

static ssize_t oom_group_write(struct file * file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char *line, *next, *page;
	int ret, len;
	LIST_HEAD(groups);

	page = (unsigned char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	len = min(count, PAGE_SIZE - 1);
	ret = copy_from_user(page, buf, len);
	if (ret)
		goto err;

	page[len] = '\0';

	next = page;
	while (1) {
		line = skip_spaces(next);
		next = strchr(line, '\n');
		if (next) {
			*next++ = '\0';
		} else if (len < count) {
			ret = line != page ? line - page : -EINVAL;
			break;
		}
		if (*line && *line != '#') {
			ret = oom_group_parse_line(&groups, line);
			if (ret)
				break;
		}
		if (!next) {
			ret = len;
			break;
		}
	}

	oom_groups_append(&groups);
err:
	free_page((unsigned long)page);
	return ret;
}

static void *oom_group_seq_start(struct seq_file *seq, loff_t *pos)
{
	read_lock_irq(&oom_group_lock);
	return seq_list_start(&oom_group_list_head, *pos);
}

static void oom_group_seq_stop(struct seq_file *s, void *v)
{
	read_unlock_irq(&oom_group_lock);
}

static int oom_group_seq_show(struct seq_file *s, void *v)
{
	struct list_head *entry = v;
	struct oom_group_pattern *p;

	p = list_entry(entry, struct oom_group_pattern, group_list);
	seq_printf(s, "%s %s %d %d\n", p->comm, p->pcomm,
			p->oom_uid, p->oom_score_adj);
	return 0;
}

static void *oom_group_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return seq_list_next(v, &oom_group_list_head, pos);
}

static struct seq_operations oom_group_seq_ops = {
	.start = oom_group_seq_start,
	.next  = oom_group_seq_next,
	.stop  = oom_group_seq_stop,
	.show  = oom_group_seq_show,
};

static int oom_group_seq_open(struct inode *inode, struct file *file)
{
	if (file->f_flags & O_TRUNC)
		oom_groups_reset();
	return seq_open(file, &oom_group_seq_ops);
}

static struct file_operations proc_oom_group_ops = {
	.owner   = THIS_MODULE,
	.open    = oom_group_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
	.write   = oom_group_write,
};

static int __init oom_group_init(void) {
	struct proc_dir_entry *proc;

	proc = proc_create("oom_score_adj", 0660,
			   proc_vz_dir, &proc_oom_group_ops);
	if (!proc)
		return -ENOMEM;
	return 0;
}

module_init(oom_group_init);
