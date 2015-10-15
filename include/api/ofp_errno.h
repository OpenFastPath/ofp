/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 */

/**
 * @file
 *
 * @brief OFP error values (errno).
 */


#ifndef __OFP_ERRNO_H__
#define __OFP_ERRNO_H__

#define	OFP_EPERM		1	/**< Operation not permitted */
#define	OFP_ENOENT		2	/**< No such file or directory */
#define	OFP_ESRCH		3	/**< No such process */
#define	OFP_EINTR		4	/**< Interrupted system call */
#define	OFP_EIO			5	/**< Input/output error */
#define	OFP_ENXIO		6	/**< Device not configured */
#define	OFP_E2BIG		7	/**< Argument list too long */
#define	OFP_ENOEXEC		8	/**< Exec format error */
#define	OFP_EBADF		9	/**< Bad file descriptor */
#define	OFP_ECHILD		10	/**< No child processes */
#define	OFP_EDEADLK		11	/**< Resource deadlock avoided */
					/**< 11 was OFP_EAGAIN */
#define	OFP_ENOMEM		12	/**< Cannot allocate memory */
#define	OFP_EACCES		13	/**< Permission denied */
#define	OFP_EFAULT		14	/**< Bad address */

#define	OFP_ENOTBLK		15	/**< Block device required */

#define	OFP_EBUSY		16	/**< Device busy */
#define	OFP_EEXIST		17	/**< File exists */
#define	OFP_EXDEV		18	/**< Cross-device link */
#define	OFP_ENODEV		19	/**< Operation not supported by device */
#define	OFP_ENOTDIR		20	/**< Not a directory */
#define	OFP_EISDIR		21	/**< Is a directory */
#define	OFP_EINVAL		22	/**< Invalid argument */
#define	OFP_ENFILE		23	/**< Too many open files in system */
#define	OFP_EMFILE		24	/**< Too many open files */
#define	OFP_ENOTTY		25	/**< Inappropriate ioctl for device */

#define	OFP_ETXTBSY		26	/**< Text file busy */

#define	OFP_EFBIG		27	/**< File too large */
#define	OFP_ENOSPC		28	/**< No space left on device */
#define	OFP_ESPIPE		29	/**< Illegal seek */
#define	OFP_EROFS		30	/**< Read-only filesystem */
#define	OFP_EMLINK		31	/**< Too many links */
#define	OFP_EPIPE		32	/**< Broken pipe */

/* math software */
#define	OFP_EDOM		33	/**< Numerical argument out of domain */
#define	OFP_ERANGE		34	/**< Result too large */

/* non-blocking and interrupt i/o */
#define	OFP_EAGAIN		35	/**< Resource temporarily unavailable */

#define	OFP_EWOULDBLOCK	OFP_EAGAIN	/**< Operation would block */
#define	OFP_EINPROGRESS		36	/**< Operation now in progress */
#define	OFP_EALREADY		37	/**< Operation already in progress */

/* ipc/network software -- argument errors */
#define	OFP_ENOTSOCK		38	/**< Socket operation on non-socket */
#define	OFP_EDESTADDRREQ	39	/**< Destination address required */
#define	OFP_EMSGSIZE		40	/**< Message too long */
#define	OFP_EPROTOTYPE		41	/**< Protocol wrong type for socket */
#define	OFP_ENOPROTOOPT		42	/**< Protocol not available */
#define	OFP_EPROTONOSUPPORT	43	/**< Protocol not supported */
#define	OFP_ESOCKTNOSUPPORT	44	/**< Socket type not supported */
#define	OFP_EOPNOTSUPP		45	/**< Operation not supported */
#define	OFP_ENOTSUP		OFP_EOPNOTSUPP	/**< Operation not supported */
#define	OFP_EPFNOSUPPORT	46	/**< Protocol family not supported */
#define	OFP_EAFNOSUPPORT	47	/**< Address family not supported by protocol family */
#define	OFP_EADDRINUSE		48	/**< Address already in use */
#define	OFP_EADDRNOTAVAIL	49	/**< Can't assign requested address */

/* ipc/network software -- operational errors */
#define	OFP_ENETDOWN		50	/**< Network is down */
#define	OFP_ENETUNREACH		51	/**< Network is unreachable */
#define	OFP_ENETRESET		52	/**< Network dropped connection on reset */
#define	OFP_ECONNABORTED	53	/**< Software caused connection abort */
#define	OFP_ECONNRESET		54	/**< Connection reset by peer */
#define	OFP_ENOBUFS		55	/**< No buffer space available */
#define	OFP_EISCONN		56	/**< Socket is already connected */
#define	OFP_ENOTCONN		57	/**< Socket is not connected */
#define	OFP_ESHUTDOWN		58	/**< Can't send after socket shutdown */
#define	OFP_ETOOMANYREFS	59	/**< Too many references: can't splice */
#define	OFP_ETIMEDOUT		60	/**< Operation timed out */
#define	OFP_ECONNREFUSED	61	/**< Connection refused */
#define	OFP_ELOOP		62	/**< Too many levels of symbolic links */
#define	OFP_ENAMETOOLONG	63	/**< File name too long */
#define	OFP_EHOSTDOWN		64	/**< Host is down */
#define	OFP_EHOSTUNREACH	65	/**< No route to host */
#define	OFP_ENOTEMPTY		66	/**< Directory not empty */

/* quotas & mush */

#define	OFP_EPROCLIM		67	/**< Too many processes */
#define	OFP_EUSERS		68	/**< Too many users */
#define	OFP_EDQUOT		69	/**< Disc quota exceeded */

/* Network File System */
#define	OFP_ESTALE		70	/**< Stale NFS file handle */
#define	OFP_EREMOTE		71	/**< Too many levels of remote in path */
#define	OFP_EBADRPC		72	/**< RPC struct is bad */
#define	OFP_ERPCMISMATCH	73	/**< RPC version wrong */
#define	OFP_EPROGUNAVAIL	74	/**< RPC prog. not avail */
#define	OFP_EPROGMISMATCH	75	/**< Program version wrong */
#define	OFP_EPROCUNAVAIL	76	/**< Bad procedure for program */

#define	OFP_ENOLCK		77	/**< No locks available */
#define	OFP_ENOSYS		78	/**< Function not implemented */

#define	OFP_EFTYPE		79	/**< Inappropriate file type or format */
#define	OFP_EAUTH		80	/**< Authentication error */
#define	OFP_ENEEDAUTH		81	/**< Need authenticator */
#define	OFP_EIDRM		82	/**< Identifier removed */
#define	OFP_ENOMSG		83	/**< No message of desired type */
#define	OFP_EOVERFLOW		84	/**< Value too large to be stored in data type */
#define	OFP_ECANCELED		85	/**< Operation canceled */
#define	OFP_EILSEQ		86	/**< Illegal byte sequence */
#define	OFP_ENOATTR		87	/**< Attribute not found */

#define	OFP_EDOOFUS		88	/**< Programming error */

#define	OFP_EBADMSG		89	/**< Bad message */
#define	OFP_EMULTIHOP		90	/**< Multihop attempted */
#define	OFP_ENOLINK		91	/**< Link has been severed */
#define	OFP_EPROTO		92	/**< Protocol error */

#define	OFP_ENOTCAPABLE		93	/**< Capabilities insufficient */
#define	OFP_ECAPMODE		94	/**< Not permitted in capability mode */

#define	OFP_ELAST		94	/**< Must be equal largest errno */

/* pseudo-errors returned inside kernel to modify return to process */
#define	OFP_ERESTART	(-1)		/**< restart syscall */
#define	OFP_EJUSTRETURN	(-2)		/**< don't modify regs, just return */
#define	OFP_ENOIOCTL	(-3)		/**< ioctl not handled by this layer */
#define	OFP_EDIRIOCTL	(-4)		/**< do direct ioctl in GEOM */

extern __thread int ofp_errno;

const char *ofp_strerror(int errnum);

#endif /* __OFP_ERRNO_H__ */
