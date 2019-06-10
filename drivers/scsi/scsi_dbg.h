/*
 *  drivers/scsi/scsi_dbg.h
 *
 *  Copyright (c) 2016 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _SCSI_DBG_H
#define _SCSI_DBG_H

#include <scsi/scsi_cmnd.h>

/*
 * Temporary debug stuff to chase missed ehandler wakeup.
 */

#define SCSI_HOST_DBG_N_ENTRIES 45 /* fit in one page */

enum scsi_dbg_type {
	SCSI_HOST_QUEUE_READY_INC_HOST_BUSY = 1, /* scsi_host_queue_ready() */
	SCSI_HOST_QUEUE_READY_DEC_HOST_BUSY,
	SCSI_KILL_REQUEST_INC_HOST_BUSY,
	SCSI_QUEUE_RQ_DEC_HOST_BUSY,
	SCSI_FINISH_COMMAND_CALLS_UNBUSY,
	SCSI_QUEUE_INSERT_CALLS_UNBUSY,
	SCSI_EH_SCMD_ADD_INC_HOST_FAILED,
	ATA_SCSI_CMD_ERROR_HANDLER_CALLS_EH_FINISH,
	ATA_EH_QC_COMPLETE_CALLS_EH_FINISH,
	SAS_EH_FINISH_CMD_CALLS_EH_FINISH,
	SCSI_EH_GET_SENSE_CALLS_EH_FINISH,
	SCSI_EH_TEST_DEVICES_CALLS_EH_FINISH,
	SCSI_EH_ABORT_CMDS_CALLS_EH_FINISH,
	SCSI_EH_STU_CALLS_EH_FINISH,
	SCSI_EH_BUS_DEVICE_RESET_CALLS_EH_FINISH,
	SCSI_EH_TARGET_RESET_CALLS_EH_FINISH,
	SCSI_EH_BUS_RESET_CALLS_EH_FINISH,
	SCSI_EH_HOST_RESET_CALLS_EH_FINISH,
	SCSI_EH_OFFLINE_SDEVS_CALLS_EH_FINISH,
	ATA_STD_END_EH_ZERO_EH_SCHEDULED,
	SAS_SCSI_RECOVER_HOST_ZERO_EH_SCHEDULED,
	ATA_STD_SCHED_EH_CALLS_SCHEDULE_EH,
	SAS_QUEUE_RESET_CALLS_SCHEDULE_EH,
	SCSI_EH_WAKEUP_EHANDLER,
	SCSI_SCHEDULE_EH_CALLS_EH_WAKEUP,
	SCSI_DEVICE_UNBUSY_CALLS_EH_WAKEUP,
	SCSI_ERROR_HANDLER_SLEEP,
	SCSI_ERROR_HANDLER_WAKEUP,
	SCSI_ERROR_HANDLER_CALLS_HANDLER,
};

struct scsi_host_log_entry {
	enum scsi_dbg_type sle_type;
	enum scsi_host_state sle_shost_state;

	int sle_host_failed;
	int sle_host_busy;
	int sle_host_blocked;
	int sle_host_eh_scheduled;

	struct task_struct *sle_task;
	char sle_comm[TASK_COMM_LEN];

	struct scsi_device *sle_sdev;
	struct scsi_cmnd   *sle_cmnd;
	struct request     *sle_req;

	ktime_t sle_ktime;
	u64     sle_jiffies;
};

struct scsi_host_dbg {
	spinlock_t		   sdbg_lock;
	struct scsi_host_log_entry sdbg_entries[SCSI_HOST_DBG_N_ENTRIES];
	int                        sdbg_next_entry;
};

#define SHOST_TO_SDBG(shost) (shost)->scsi_mq_reserved3

static inline void
scsi_debug_log(struct Scsi_Host *shost, enum scsi_dbg_type type,
	       struct scsi_device *sdev, struct scsi_cmnd *cmnd,
	       struct request *req)
{
	struct scsi_host_dbg *s = SHOST_TO_SDBG(shost);
	struct scsi_host_log_entry *e;
	unsigned long irq_flags;

	spin_lock_irqsave(&s->sdbg_lock, irq_flags);
	e = &s->sdbg_entries[s->sdbg_next_entry];

	e->sle_type = type;
	e->sle_sdev = sdev;
	e->sle_cmnd = cmnd;
	e->sle_req  = req;

	e->sle_shost_state       = shost->shost_state;
	e->sle_host_failed       = shost->host_failed;
	e->sle_host_busy         = atomic_read(&shost->host_busy);
	e->sle_host_blocked      = atomic_read(&shost->host_blocked);
	e->sle_host_eh_scheduled = shost->host_eh_scheduled;

	e->sle_task = current;
	memcpy(e->sle_comm, current->comm, TASK_COMM_LEN);

	e->sle_ktime   = ktime_get();
	e->sle_jiffies = jiffies;

	s->sdbg_next_entry++;
	if (s->sdbg_next_entry == SCSI_HOST_DBG_N_ENTRIES)
		s->sdbg_next_entry = 0;
	spin_unlock_irqrestore(&s->sdbg_lock, irq_flags);
}

static inline void
scsi_debug_log_cmnd(enum scsi_dbg_type type, struct scsi_cmnd *cmnd)
{
	scsi_debug_log(cmnd->device->host, type, cmnd->device, cmnd,
		       cmnd->request);
}

static inline void
scsi_debug_log_shost(enum scsi_dbg_type type, struct Scsi_Host *shost)
{
	scsi_debug_log(shost, type, NULL, NULL, NULL);
}

static inline void
scsi_debug_log_sdev(enum scsi_dbg_type type, struct scsi_device *sdev)
{
	scsi_debug_log(sdev->host, type, sdev, NULL, NULL);
}

#endif /* _SCSI_DBG_H */
