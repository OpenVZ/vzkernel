/*
 * Remap qrwlock functions back to their rwlock equivalents
 */
#ifndef __ASM_GENERIC_QRWLOCK_REMAP_H
#define __ASM_GENERIC_QRWLOCK_REMAP_H

typedef rwlock_t qrwlock_t;

#define qread_lock(l)		read_lock(l)
#define qread_lock_unfair(l)	read_lock(l)
#define qread_trylock(l)	read_trylock(l)
#define qread_unlock(l)		read_unlock(l)

#define qread_lock_bh(l)	read_lock_bh(l)
#define qread_trylock_bh(l)	read_trylock_bh(l)
#define qread_unlock_bh(l)	read_unlock_bh(l)

#define qread_lock_irq(l)	read_lock_irq(l)
#define qread_trylock_irq(l)	read_trylock_irq(l)
#define qread_unlock_irq(l)	read_unlock_irq(l)

#define qread_lock_irqsave(l,f)		read_lock_irqsave(l,f)
#define qread_trylock_irqsave(l,f)	read_trylock_irqsave(l,f)
#define qread_unlock_irqrestore(l,f)	read_unlock_irqrestore(l,f)

#define qwrite_lock(l)		write_lock(l)
#define qwrite_trylock(l)	write_trylock(l)
#define qwrite_unlock(l)	write_unlock(l)

#define qwrite_lock_bh(l)	write_lock_bh(l)
#define qwrite_trylock_bh(l)	write_trylock_bh(l)
#define qwrite_unlock_bh(l)	write_unlock_bh(l)

#define qwrite_lock_irq(l)	write_lock_irq(l)
#define qwrite_trylock_irq(l)	write_trylock_irq(l)
#define qwrite_unlock_irq(l)	write_unlock_irq(l)

#define qwrite_lock_irqsave(l,f)	write_lock_irqsave(l,f)
#define qwrite_trylock_irqsave(l,f)	write_trylock_irqsave(l,f)
#define qwrite_unlock_irqrestore(l,f)	write_unlock_irqrestore(l,f)

#define DEFINE_QRWLOCK(l)	DEFINE_RWLOCK(l)
#define __QRW_LOCK_UNLOCKED(l)	__RW_LOCK_UNLOCKED(l)
#define qrwlock_init(l)		rwlock_init(l)

#endif
