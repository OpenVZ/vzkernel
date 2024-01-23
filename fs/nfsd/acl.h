/*
 *  Common NFSv4 ACL handling definitions.
 *
 *  Copyright (c) 2002 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Marius Aamodt Eriksen <marius@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef LINUX_NFS4_ACL_H
#define LINUX_NFS4_ACL_H

#include <linux/posix_acl.h>

/*
 * Maximum ACL we'll accept from a client; chosen (somewhat
 * arbitrarily) so that kmalloc'ing the ACL shouldn't require a
 * high-order allocation.  This allows 204 ACEs on x86_64:
 */
#define NFS4_ACL_MAX ((PAGE_SIZE - sizeof(struct nfs4_acl)) \
			/ sizeof(struct nfs4_ace))

int nfs4_acl_bytes(int entries);
int nfs4_acl_get_whotype(char *, u32);
__be32 nfs4_acl_write_who(struct xdr_stream *xdr, int who);

#define NFS4_ACL_TYPE_DEFAULT	0x01
#define NFS4_ACL_DIR		0x02
#define NFS4_ACL_OWNER		0x04

struct nfs4_acl *nfs4_acl_posix_to_nfsv4(struct dentry *dentry,
				struct posix_acl *,
				struct posix_acl *, unsigned int flags);
int nfs4_acl_nfsv4_to_posix(struct nfs4_acl *, struct posix_acl **,
				struct posix_acl **, unsigned int flags);

#endif /* LINUX_NFS4_ACL_H */
