/*
 * The owner field of the rw_semaphore structure will be set to
 * RWSEM_READ_OWNED when a reader grabs the lock. A writer will clear
 * the owner field when it unlocks. A reader, on the other hand, will
 * not touch the owner field when it unlocks.
 *
 * In essence, the owner field now has the following 3 states:
 *  1) 0
 *     - lock is free or the owner hasn't set the field yet
 *  2) RWSEM_READER_OWNED
 *     - lock is currently or previously owned by readers (lock is free
 *       or not set by owner yet)
 *  3) Other non-zero value
 *     - a writer owns the lock
 */
#define RWSEM_READER_OWNED	((struct task_struct *)1UL)

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
/*
 * All writes to owner are protected by WRITE_ONCE() to make sure that
 * store tearing can't happen as optimistic spinners may read and use
 * the owner value concurrently without lock. Read from owner, however,
 * may not need READ_ONCE() as long as the pointer value is only used
 * for comparison and isn't being dereferenced.
 */
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
	WRITE_ONCE(sem->owner, current);
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
	WRITE_ONCE(sem->owner, NULL);
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
	/*
	 * We check the owner value first to make sure that we will only
	 * do a write to the rwsem cacheline when it is really necessary
	 * to minimize cacheline contention.
	 */
	if (sem->owner != RWSEM_READER_OWNED)
		WRITE_ONCE(sem->owner, RWSEM_READER_OWNED);
}

static inline bool rwsem_owner_is_writer(struct task_struct *owner)
{
	return owner && owner != RWSEM_READER_OWNED;
}

static inline bool rwsem_owner_is_reader(struct task_struct *owner)
{
	return owner == RWSEM_READER_OWNED;
}

/*
 * struct slist contains a pointer to a struct list circular list.
 * The head of the slist is the entry pointed to by the slist. The tail
 * is the one pointed to by the "prev" member of the head.
 */
static inline void INIT_SLIST_HEAD(struct slist_head *head)
{
	WRITE_ONCE(head->next, (void *)head);
}

static inline bool slist_is_singular(struct slist_head *head)
{
	return !slist_empty(head) && list_empty(head->next);
}

static inline void slist_add_tail(struct list_head  *new,
				  struct slist_head *head)
{
	if (slist_empty(head)) {
		INIT_LIST_HEAD(new);
		head->next = new;
	} else {
		list_add_tail(new, head->next);
	}
}

static inline void slist_del(struct list_head  *node,
			     struct slist_head *head)
{
	if (head->next == node) {
		if (list_empty(node)) {
			INIT_SLIST_HEAD(head);
			node->next = LIST_POISON1;
			node->prev = LIST_POISON2;
			return;
		}
		head->next = node->next;
	}
	list_del(node);
}

#else
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
}

#define slist_head			list_head
#define INIT_SLIST_HEAD(head)		INIT_LIST_HEAD(head)
#define slist_is_singular(head)		list_is_singular(head)
#define slist_add_tail(new, head)	list_add_tail(new, head)
#define slist_del(node, head)		list_del(node)
#endif
