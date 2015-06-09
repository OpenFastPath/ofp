/*-
 * Copyright (c) 1982, 1986, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2015 Nokia Solutions and Networks
 * Copyright (c) 2015 Enea Software AB
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)sys_socket.c	8.1 (Berkeley) 6/10/93
 */

#include "ofpi_protosw.h"
#include "ofpi_socketvar.h"
#include "ofpi_ioctl.h"
#include "ofpi_sockstate.h"
#include "ofpi_errno.h"

int
ofp_soo_ioctl(struct socket *so, uint32_t cmd, void *data, struct ofp_ucred *active_cred,
    struct thread *td)
{
	int error = 0;
	(void)active_cred;

	switch (cmd) {
	case OFP_FIONBIO:
		OFP_SOCK_LOCK(so);
		if (*(int *)data)
			so->so_state |= SS_NBIO;
		else
			so->so_state &= ~SS_NBIO;
		OFP_SOCK_UNLOCK(so);
		break;

	case OFP_FIOASYNC:
		/*
		 * XXXRW: This code separately acquires OFP_SOCK_LOCK(so) and
		 * SOCKBUF_LOCK(&so->so_rcv) even though they are the same
		 * mutex to avoid introducing the assumption that they are
		 * the same.
		 */
		if (*(int *)data) {
			OFP_SOCK_LOCK(so);
			so->so_state |= SS_ASYNC;
			OFP_SOCK_UNLOCK(so);
			SOCKBUF_LOCK(&so->so_rcv);
			so->so_rcv.sb_flags |= SB_ASYNC;
			SOCKBUF_UNLOCK(&so->so_rcv);
			SOCKBUF_LOCK(&so->so_snd);
			so->so_snd.sb_flags |= SB_ASYNC;
			SOCKBUF_UNLOCK(&so->so_snd);
		} else {
			OFP_SOCK_LOCK(so);
			so->so_state &= ~SS_ASYNC;
			OFP_SOCK_UNLOCK(so);
			SOCKBUF_LOCK(&so->so_rcv);
			so->so_rcv.sb_flags &= ~SB_ASYNC;
			SOCKBUF_UNLOCK(&so->so_rcv);
			SOCKBUF_LOCK(&so->so_snd);
			so->so_snd.sb_flags &= ~SB_ASYNC;
			SOCKBUF_UNLOCK(&so->so_snd);
		}
		break;

	case OFP_FIONREAD:
		/* Unlocked read. */
		*(int *)data = so->so_rcv.sb_cc;
		break;

	case OFP_FIONWRITE:
		/* Unlocked read. */
		*(int *)data = so->so_snd.sb_cc;
		break;

	case OFP_FIONSPACE:
		if ((so->so_snd.sb_hiwat < so->so_snd.sb_cc) ||
		    (so->so_snd.sb_mbmax < so->so_snd.sb_mbcnt))
			*(int *)data = 0;
		else
			*(int *)data = sbspace(&so->so_snd);
		break;
#if 0
	case OFP_FIOSETOWN:
		error = fsetown(*(int *)data, &so->so_sigio);
		break;

	case OFP_FIOGETOWN:
		*(int *)data = fgetown(&so->so_sigio);
		break;

	case OFP_SIOCSPGRP:
		error = fsetown(-(*(int *)data), &so->so_sigio);
		break;

	case OFP_SIOCGPGRP:
		*(int *)data = -fgetown(&so->so_sigio);
		break;
#endif
	case OFP_SIOCATMARK:
		/* Unlocked read. */
		*(int *)data = (so->so_rcv.sb_state & SBS_RCVATMARK) != 0;
		break;

	/* Interface specific ioctls */
	case OFP_SIOCGIFCONF:
	case OFP_OSIOCGIFCONF:
	case OFP_SIOCIFCREATE:
	case OFP_SIOCIFCREATE2:
	case OFP_SIOCIFDESTROY:
	case OFP_SIOCIFGCLONERS:
	case OFP_SIOCGIFGMEMB:
		error = OFP_EOPNOTSUPP;
		break;

	default:
		error = ((*so->so_proto->pr_usrreqs->pru_control)
			 (so, cmd, data, 0, td));
		break;
	}
	return (error);
}
