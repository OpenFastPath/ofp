/*-
 * Copyright (c) 2014 Nokia
 * Copyright (c) 2014 ENEA Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_errno.h"

static const char *ofp_errmsgs[] = {
"",
"Operation not permitted",	/* OFP_EPERM */
"No such file or directory",	/* OFP_ENOENT */
"No such process",	/* OFP_ESRCH */
"Interrupted system call",	/* OFP_EINTR */
"Input/output error",	/* OFP_EIO */
"Device not configured",	/* OFP_ENXIO */
"Argument list too long",	/* OFP_E2BIG */
"Exec format error",	/* OFP_ENOEXEC */
"Bad file descriptor",	/* OFP_EBADF */
"No child processes",	/* OFP_ECHILD */
"Resource deadlock avoided",	/* OFP_EDEADLK */

"Cannot allocate memory",	/* OFP_ENOMEM */
"Permission denied",	/* OFP_EACCES */
"Bad address",	/* OFP_EFAULT */

"Block device required",	/* OFP_ENOTBLK */

"Device busy",	/* OFP_EBUSY */
"File exists",	/* OFP_EEXIST */
"Cross-device link",	/* OFP_EXDEV */
"Operation not supported by device",	/* OFP_ENODEV */
"Not a directory",	/* OFP_ENOTDIR */
"Is a directory",	/* OFP_EISDIR */
"Invalid argument",	/* OFP_EINVAL */
"Too many open files in system",	/* OFP_ENFILE */
"Too many open files",	/* OFP_EMFILE */
"Inappropriate ioctl for device",	/* OFP_ENOTTY */

"Text file busy",	/* OFP_ETXTBSY */

"File too large",	/* OFP_EFBIG */
"No space left on device",	/* OFP_ENOSPC */
"Illegal seek",	/* OFP_ESPIPE */
"Read-only filesystem",	/* OFP_EROFS */
"Too many links",	/* OFP_EMLINK */
"Broken pipe",	/* OFP_EPIPE */

"Numerical argument out of domain",	/* OFP_EDOM */
"Result too large",	/* OFP_ERANGE */

"Resource temporarily unavailable",	/* OFP_EAGAIN */

"Operation now in progress",	/* OFP_EINPROGRESS */
"Operation already in progress",	/* OFP_EALREADY */

"Socket operation on non-socket",	/* OFP_ENOTSOCK */
"Destination address required",	/* OFP_EDESTADDRREQ */
"Message too long",	/* OFP_EMSGSIZE */
"Protocol wrong type for socket",	/* OFP_EPROTOTYPE */
"Protocol not available",	/* OFP_ENOPROTOOPT */
"Protocol not supported",	/* OFP_EPROTONOSUPPORT */
"Socket type not supported",	/* OFP_ESOCKTNOSUPPORT */
"Operation not supported",	/* OFP_ENOTSUP */
"Protocol family not supported",	/* OFP_EPFNOSUPPORT */
"Address family not supported by protocol family",	/* OFP_EAFNOSUPPORT */
"Address already in use",	/* OFP_EADDRINUSE */
"Can't assign requested address",	/* OFP_EADDRNOTAVAIL */

"Network is down",	/* OFP_ENETDOWN */
"Network is unreachable",	/* OFP_ENETUNREACH */
"Network dropped connection on reset",	/* OFP_ENETRESET */
"Software caused connection abort",	/* OFP_ECONNABORTED */
"Connection reset by peer",	/* OFP_ECONNRESET */
"No buffer space available",	/* OFP_ENOBUFS */
"Socket is already connected",	/* OFP_EISCONN */
"Socket is not connected",	/* OFP_ENOTCONN */
"Can't send after socket shutdown",	/* OFP_ESHUTDOWN */
"Too many references: can't splice",	/* OFP_ETOOMANYREFS */
"Operation timed out",	/* OFP_ETIMEDOUT */
"Connection refused",	/* OFP_ECONNREFUSED */

"Too many levels of symbolic links",	/* OFP_ELOOP */

"File name too long",	/* OFP_ENAMETOOLONG */

"Host is down",	/* OFP_EHOSTDOWN */
"No route to host",	/* OFP_EHOSTUNREACH */

"Directory not empty",	/* OFP_ENOTEMPTY */

"Too many processes",	/* OFP_EPROCLIM */
"Too many users",	/* OFP_EUSERS */
"Disc quota exceeded",	/* OFP_EDQUOT */

"Stale NFS file handle",	/* OFP_ESTALE */
"Too many levels of remote in path",	/* OFP_EREMOTE */
"RPC struct is bad",	/* OFP_EBADRPC */
"RPC version wrong",	/* OFP_ERPCMISMATCH */
"RPC prog. not avail",	/* OFP_EPROGUNAVAIL */
"Program version wrong",	/* OFP_EPROGMISMATCH */
"Bad procedure for program",	/* OFP_EPROCUNAVAIL */

"No locks available",	/* OFP_ENOLCK */
"Function not implemented",	/* OFP_ENOSYS */

"Inappropriate file type or format",	/* OFP_EFTYPE */
"Authentication error",	/* OFP_EAUTH */
"Need authenticator",	/* OFP_ENEEDAUTH */
"Identifier removed",	/* OFP_EIDRM */
"No message of desired type",	/* OFP_ENOMSG */
"Value too large to be stored in data type",	/* OFP_EOVERFLOW */
"Operation canceled",	/* OFP_ECANCELED */
"Illegal byte sequence",	/* OFP_EILSEQ */
"Attribute not found",	/* OFP_ENOATTR */

"Programming error",	/* OFP_EDOOFUS */

"Bad message",	/* OFP_EBADMSG */
"Multihop attempted",	/* OFP_EMULTIHOP */
"Link has been severed",	/* OFP_ENOLINK */
"Protocol error",	/* OFP_EPROTO */

"Capabilities insufficient",	/* OFP_ENOTCAPABLE */
"Not permitted in capability mode",	/* OFP_ECAPMODE */
};

__thread int ofp_errno;

const char *ofp_strerror(int errnum)
{
	if (errnum < 0)
		errnum = -errnum;

	if (errnum > OFP_ELAST)
		return "";

	return ofp_errmsgs[errnum];
}
