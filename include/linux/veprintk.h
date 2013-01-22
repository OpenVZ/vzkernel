/*
 *  include/linux/veprintk.h
 *
 *  Copyright (C) 2006  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __VE_PRINTK_H__
#define __VE_PRINTK_H__

#if 0 /* until ve_printk is fixed */

#define ve_log_wait		(*(get_exec_env()->_log_wait))
#define ve_log_start		(*(get_exec_env()->_log_start))
#define ve_log_end		(*(get_exec_env()->_log_end))
#define ve_logged_chars		(*(get_exec_env()->_logged_chars))
#define ve_log_buf		(get_exec_env()->log_buf)
#define ve_log_buf_len		(ve_is_super(get_exec_env()) ? \
				log_buf_len : VE_DEFAULT_LOG_BUF_LEN)
#define VE_LOG_BUF_MASK		(ve_log_buf_len - 1)
#define VE_LOG_BUF(idx)		(ve_log_buf[(idx) & VE_LOG_BUF_MASK])

#else

#define ve_log_wait		log_wait
#define ve_log_start		log_start
#define ve_log_end		log_end
#define ve_logged_chars		logged_chars
#define ve_log_buf		log_buf
#define ve_log_buf_len		log_buf_len
#define VE_LOG_BUF_MASK		LOG_BUF_MASK
#define VE_LOG_BUF(idx)		LOG_BUF(idx)

#endif /* CONFIG_VE */
#endif /* __VE_PRINTK_H__ */
