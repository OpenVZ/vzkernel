#ifndef _PCS_FLOW_DETECT_STUB_H_
#define _PCS_FLOW_DETECT_STUB_H_ 1

/* TODO:!!! this is stump for  flow_detection */

/* This should be enough for 1000 iops, otherwise lifetime is to be decreased or/and limit increased. */
#define PCS_FLOW_LIFETIME	(512)
#define PCS_FLOW_LIMIT_DFLT	(512)

#define PCS_FLOW_RECENTTIME	(50)
#define PCS_FLOW_THRESH		(6)

struct pcs_flow_node
{
	int STUMB;
};

struct pcs_flow_table
{
	struct pcs_flow_node *STUMB;
};

struct pcs_flow_table_global
{
	struct pcs_flow_table *STUMB;
	int		       nflows;
};

struct pcs_cs;

static void pcs_flow_table_global_init(struct pcs_flow_table_global * gtab) __attribute__((unused));
static void pcs_flow_table_global_fini(struct pcs_flow_table_global * gtab) __attribute__((unused));
static void pcs_flow_table_init(struct pcs_flow_table * tab, struct pcs_flow_table_global * gtab) __attribute__((unused));
static void pcs_flow_table_fini(struct pcs_flow_table * tab, struct pcs_flow_table_global * gtab) __attribute__((unused));
static struct pcs_flow_node * pcs_flow_record(struct pcs_flow_table * tab, int dir, u64 start, unsigned int len,
				       struct pcs_flow_table_global * gtab) __attribute__((unused));
static void pcs_flow_confirm(struct pcs_flow_node * fl, struct pcs_flow_table * tab, int dir, u64 start, unsigned int len,
			      struct pcs_flow_table_global * gtab) __attribute__((unused));
static void pcs_flow_truncate(struct pcs_flow_table * tab, u64 new_size, struct pcs_flow_table_global * gtab) __attribute__((unused));
static int pcs_flow_analysis(struct pcs_flow_table_global * gtab) __attribute__((unused));
static int pcs_flow_cs_analysis(struct pcs_cs * cs) __attribute__((unused));
static void pcs_flow_bind_cs(struct pcs_flow_node * fl, struct pcs_cs * cs) __attribute__((unused));
static void pcs_flow_cs_unbind_all(struct pcs_cs * cs) __attribute__((unused));
static void pcs_flow_put(struct pcs_flow_node * fl, struct pcs_flow_table_global * gtab) __attribute__((unused));
static struct pcs_flow_node * pcs_flow_get(struct pcs_flow_node * fl) __attribute__((unused));
static int pcs_flow_sequential(struct pcs_flow_node * fl) __attribute__((unused));






static void pcs_flow_table_global_init(struct pcs_flow_table_global * gtab) {}
static void pcs_flow_table_global_fini(struct pcs_flow_table_global * gtab) {}
static void pcs_flow_table_init(struct pcs_flow_table * tab, struct pcs_flow_table_global * gtab) {}
static void pcs_flow_table_fini(struct pcs_flow_table * tab, struct pcs_flow_table_global * gtab) {}

static struct pcs_flow_node * pcs_flow_record(struct pcs_flow_table * tab, int dir, u64 start, unsigned int len,
				       struct pcs_flow_table_global * gtab)
{
	return NULL;
}
static void pcs_flow_confirm(struct pcs_flow_node * fl, struct pcs_flow_table * tab, int dir, u64 start, unsigned int len,
			      struct pcs_flow_table_global * gtab) {}
static void pcs_flow_truncate(struct pcs_flow_table * tab, u64 new_size, struct pcs_flow_table_global * gtab) {}
static int pcs_flow_analysis(struct pcs_flow_table_global * gtab) { return 0; }
static int pcs_flow_cs_analysis(struct pcs_cs * cs) {return 0;}
static void pcs_flow_bind_cs(struct pcs_flow_node * fl, struct pcs_cs * cs) {}
static void pcs_flow_cs_unbind_all(struct pcs_cs * cs) {}

static void pcs_flow_put(struct pcs_flow_node * fl, struct pcs_flow_table_global * gtab) {}
static struct pcs_flow_node * pcs_flow_get(struct pcs_flow_node * fl) {return NULL;}
static int pcs_flow_sequential(struct pcs_flow_node * fl) {return 0;}


#endif /* _PCS_FLOW_DETECT_STUB_H_ */
