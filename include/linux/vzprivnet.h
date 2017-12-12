/*
 *  include/linux/vzprivnet.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef __IP_VZPRIVNET_H__
#define __IP_VZPRIVNET_H__

extern int vzpn_handle_bridged;
extern int vzpn_filter_host;

struct proc_dir_entry;
extern struct proc_dir_entry *vzpriv_proc_dir;

struct seq_file;
typedef void (*vzprivnet_show_fn)(struct seq_file *);
void vzprivnet_reg_show(vzprivnet_show_fn);
void vzprivnet_unreg_show(vzprivnet_show_fn);

#define is_eol(ch)	((ch) == '\0' || (ch) == '\n')

#define VZPRIVNET_STRONG       0
#define VZPRIVNET_WEAK         1
#define VZPRIVNET_INET         2

#endif
