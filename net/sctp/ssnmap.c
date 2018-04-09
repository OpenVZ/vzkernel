/* SCTP kernel implementation
 * Copyright (c) 2003 International Business Machines, Corp.
 *
 * This file is part of the SCTP kernel implementation
 *
 * These functions manipulate sctp SSN tracker.
 *
 * This SCTP implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This SCTP implementation is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ************************
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <lksctp-developers@lists.sourceforge.net>
 *
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by:
 *    Jon Grimm             <jgrimm@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>

/* Allocate memory pages for one type of stream (in or out). */
static int sctp_stream_alloc(struct sctp_stream *stream, __u16 len, gfp_t gfp)
{
	int err = -ENOMEM;

	stream->ssn = flex_array_alloc(sizeof(__u16), len, gfp);
	if (stream->ssn) {
		err = flex_array_prealloc(stream->ssn, 0, len, gfp);
		if (err) {
			flex_array_free(stream->ssn);
			stream->ssn = NULL;
		}
		stream->len = len;
	}

	return err;
}

/* Free memory pages for one type of stream (in or out). */
static void sctp_stream_free(struct sctp_stream *stream)
{
	if (stream->ssn)
		flex_array_free(stream->ssn);
}

/* Clear all SSNs for one type of stream (in or out). */
static void sctp_stream_clear(struct sctp_stream *stream)
{
	unsigned int i;

	for (i = 0; i < stream->len; i++)
		flex_array_clear(stream->ssn, i);
}

/* Create a new sctp_ssnmap.
 * Allocate room to store at least 'in' + 'out' SSNs.
 */
struct sctp_ssnmap *sctp_ssnmap_new(__u16 in, __u16 out, gfp_t gfp)
{
	struct sctp_ssnmap *retval;
	int err;

	retval = (struct sctp_ssnmap *)kzalloc(sizeof(struct sctp_ssnmap), gfp);
	if (!retval)
		goto fail;

	err = sctp_stream_alloc(&retval->in, in, gfp);
	if (err)
		goto fail_map;

	err = sctp_stream_alloc(&retval->out, out, gfp);
	if (err)
		goto fail_map;

	SCTP_DBG_OBJCNT_INC(ssnmap);

	return retval;

fail_map:
	sctp_stream_free(&retval->in);
	sctp_stream_free(&retval->out);
	kfree(retval);
fail:
	return NULL;
}

/* Clear out the ssnmap streams.  */
void sctp_ssnmap_clear(struct sctp_ssnmap *map)
{
	sctp_stream_clear(&map->in);
	sctp_stream_clear(&map->out);
}

/* Dispose of a ssnmap.  */
void sctp_ssnmap_free(struct sctp_ssnmap *map)
{
	if (unlikely(!map))
		return;

	sctp_stream_free(&map->in);
	sctp_stream_free(&map->out);
	kfree(map);

	SCTP_DBG_OBJCNT_DEC(ssnmap);
}
