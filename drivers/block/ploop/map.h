#ifndef __PLOOP_MAP_H
#define __PLOOP_MAP_H

/* This defines slot in mapping page. Right now it is 32 bit
 * and therefore it directly matches ploop1 structure. */
typedef u32 map_index_t;

#define INDEX_PER_PAGE	(PAGE_SIZE / sizeof(map_index_t))
#define INDEX_PER_PAGE_SHIFT (PAGE_SHIFT - 2)

/*
 * Additional information for each page is:
 * 1. rb tree link
 * 2. Page
 * 3. mn_start, mn_end - the first and the last index
 * (correspondingly) the page maps to iblocks.
 * 4. lru linkage
 * 5. delta level of whole page, it is delta, where this page
 *    is backed.
 * 6. Array of delta levels for each map_index in the page.
 *    If page is backed at level N, those levels cannot be >N.
 *    If all the levels == N, array of levels is not allocated.
 *    When at least one level < N, it is stored in the array.
 *    Note, that in this case exporting page to disk implies
 *    clearing irrelevant entries.
 */

struct map_node
{
	struct rb_node		rb_link;
	cluster_t		mn_start;
	cluster_t		mn_end;
	unsigned long		state;
	atomic_t		refcnt;
	struct ploop_map	*parent;

	struct page		*page;
	struct list_head	lru;
	u8			*levels;

	/* List of preq's blocking on this mapping.
	 *
	 * We queue here several kinds of requests:
	 * 1. If mapping is not uptodate, all the requests which need
	 *    this mapping are queued here. preq state is ENTRY.
	 * 2. If preq requires index update and it is delayed
	 *    because writeback is in progress. preq state is INDEX_DELAY,
	 *    new index is kept in preq->iblock.
	 * 3. If preq's started index update, preq state is INDEX_WB,
	 *    new indices are sent to io, but they are not inserted
	 *    into mapping until writeback is complete.
	 */
	struct list_head	io_queue;
};

#endif /* __PLOOP_MAP_H */
