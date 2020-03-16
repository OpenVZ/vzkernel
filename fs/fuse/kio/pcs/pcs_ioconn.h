#ifndef _PCS_IOCONN_H_
#define _PCS_IOCONN_H_ 1

#include "pcs_types.h"

struct pcs_ioconn
{
	void(*destruct)(struct pcs_ioconn *); /* called in pcs_ioconn_unregister() */
};

#endif /* _PCS_IOCONN_H_ */
