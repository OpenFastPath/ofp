/*-
 * Copyright (c) 1982, 1986, 1990, 1993, 1994
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
 *	@(#)sockio.h	8.1 (Berkeley) 3/28/94
 * $FreeBSD: release/9.1.0/sys/sys/sockio.h 223735 2011-07-03 12:22:02Z bz $
 */

#ifndef _SYS_IOCTL_H_
#define	_SYS_IOCTL_H_

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/*
 * Buffer with length to be used in SIOCGIFDESCR/SIOCSIFDESCR requests
 */
struct ofp_ifreq_buffer {
	size_t	length;
	void	*buffer;
};

/*
 * Interface request structure used for socket
 * ofp_ioctl's.  All interface ioctl's must have parameter
 * definitions which begin with ifr_name.  The
 * remainder may be interface specific.
 */
struct ofp_ifreq {
	char	ifr_name[OFP_IFNAMSIZ];		/* if name, e.g. "en0" */
	union {
		struct	ofp_sockaddr ifru_addr;
		struct	ofp_sockaddr ifru_dstaddr;
		struct	ofp_sockaddr ifru_broadaddr;
		struct	ofp_ifreq_buffer ifru_buffer;
		short	ifru_flags[2];
		short	ifru_index;
		int	ifru_jid;
		int	ifru_metric;
		int	ifru_mtu;
		int	ifru_phys;
		int	ifru_media;
		char *	ifru_data;
		int	ifru_cap[2];
		uint32_t	ifru_fib;
	} ifr_ifru;
#define	ifr_addr	ifr_ifru.ifru_addr	/* address */
#define	ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-to-p link */
#define	ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address */
#define	ifr_buffer	ifr_ifru.ifru_buffer	/* user supplied buffer with its length */
#define	ifr_flags	ifr_ifru.ifru_flags[0]	/* flags (low 16 bits) */
#define	ifr_flagshigh	ifr_ifru.ifru_flags[1]	/* flags (high 16 bits) */
#define	ifr_jid		ifr_ifru.ifru_jid	/* jail/vnet */
#define	ifr_metric	ifr_ifru.ifru_metric	/* metric */
#define	ifr_mtu		ifr_ifru.ifru_mtu	/* mtu */
#define ifr_phys	ifr_ifru.ifru_phys	/* physical wire */
#define ifr_media	ifr_ifru.ifru_media	/* physical media */
#define	ifr_data	ifr_ifru.ifru_data	/* for use by interface */
#define	ifr_reqcap	ifr_ifru.ifru_cap[0]	/* requested capabilities */
#define	ifr_curcap	ifr_ifru.ifru_cap[1]	/* current capabilities */
#define	ifr_index	ifr_ifru.ifru_index	/* interface index */
#define	ifr_fib		ifr_ifru.ifru_fib	/* interface fib */
};

struct ofp_ifconf {
	int	ifc_len;		/* size of associated buffer */
	int	ifc_current_len;
	union {
		char *	ifcu_buf;
		struct ofp_ifreq *ifcu_req;
	} ifc_ifcu;
#define	ifc_buf	ifc_ifcu.ifcu_buf	/* buffer address */
#define	ifc_req	ifc_ifcu.ifcu_req	/* array of structures returned */
};

/*
 * Structure used to query names of interface cloners.
 */

struct ofp_if_clonereq {
	int	ifcr_total;		/* total cloners (out) */
	int	ifcr_count;		/* room for this many in user buffer */
	char	*ifcr_buffer;		/* buffer for cloner names */
};

/*
 * Used to lookup groups for an interface
 */
struct ofp_ifgroupreq {
	char	ifgr_name[OFP_IFNAMSIZ];
	uint32_t	ifgr_len;
	union {
		char	ifgru_group[OFP_IFNAMSIZ];
		struct	ifg_req *ifgru_groups;
	} ifgr_ifgru;
#define ifgr_group	ifgr_ifgru.ifgru_group
#define ifgr_groups	ifgr_ifgru.ifgru_groups
};

struct ofp_ifaliasreq {
	char	ifra_name[OFP_IFNAMSIZ];		/* if name, e.g. "en0" */
	struct	ofp_sockaddr ifra_addr;
	struct	ofp_sockaddr ifra_broadaddr;
	struct	ofp_sockaddr ifra_mask;
};

struct ofp_in_aliasreq {
	char	ifra_name[OFP_IFNAMSIZ];		/* if name, e.g. "en0" */
	struct	ofp_sockaddr_in ifra_addr;
	struct	ofp_sockaddr_in ifra_broadaddr;
#define ifra_dstaddr ifra_broadaddr
	struct	ofp_sockaddr_in ifra_mask;
};

struct ofp_in_tunreq {
	char	iftun_name[OFP_IFNAMSIZ];		/* if name, e.g. "gre1" */
	struct	ofp_sockaddr_in iftun_addr;
	struct	ofp_sockaddr_in iftun_p2p_addr;
	struct	ofp_sockaddr_in iftun_local_addr;
	struct	ofp_sockaddr_in iftun_remote_addr;
	int	iftun_vrf;
};

/*
 * Structure for SIOC[AGD]LIFADDR
 */
struct ofp_sockaddr_storage {
	unsigned char	ss_len;		/* address length */
	ofp_sa_family_t	ss_family;	/* address family */
};

struct ofp_if_laddrreq {
	char	iflr_name[OFP_IFNAMSIZ];
	uint32_t	flags;
#define	IFLR_PREFIX	0x8000  /* in: prefix given  out: kernel fills id */
	uint32_t	prefixlen;         /* in/out */
	struct ofp_sockaddr_storage addr;   /* in/out */
	struct ofp_sockaddr_storage dstaddr; /* out */
};

/*
 * Structure for SIOCADDRT and SIOCDELRT
 */
struct ofp_rtentry {
	struct ofp_sockaddr	rt_dst;		/* target address		*/
	struct ofp_sockaddr	rt_gateway;	/* gateway addr (RTF_GATEWAY)	*/
	struct ofp_sockaddr	rt_genmask;	/* target network mask (IP)	*/
	int			rt_vrf;
	uint16_t		rt_flags;
	int16_t			rt_metric;	/* +1 for binary compatibility!	*/
	char			*rt_dev;	/* forcing the device at add	*/
	unsigned long		rt_mtu;		/* per route MTU/Window 	*/
#define rt_mss	rt_mtu				/* Compatibility :-(            */
	unsigned long		rt_window;	/* Window clamping 		*/
	unsigned short		rt_irtt;	/* Initial RTT			*/
};

/*
 * Ioctl's have the command encoded in the lower word, and the size of
 * any in or out parameters in the upper word.  The high 3 bits of the
 * upper word are used to encode the in/out status of the parameter.
 */
#define	OFP_IOCPARM_SHIFT	13		/* number of bits for ofp_ioctl size */
#define	OFP_IOCPARM_MASK	((1 << OFP_IOCPARM_SHIFT) - 1) /* parameter length mask */
#define	OFP_IOCPARM_LEN(x)	(((x) >> 16) & OFP_IOCPARM_MASK)
#define	OFP_IOCBASECMD(x)	((x) & ~(OFP_IOCPARM_MASK << 16))
#define	OFP_IOCGROUP(x)	(((x) >> 8) & 0xff)

#define	OFP_IOCPARM_MAX	(1 << OFP_IOCPARM_SHIFT)	/* max size of ofp_ioctl */
#define	OFP_IOC_VOID	0x20000000		/* no parameters */
#define	OFP_IOC_OUT		0x40000000		/* copy out parameters */
#define	OFP_IOC_IN		0x80000000		/* copy in parameters */
#define	OFP_IOC_INOUT	(OFP_IOC_IN|OFP_IOC_OUT)
#define	OFP_IOC_DIRMASK	(OFP_IOC_VOID|OFP_IOC_OUT|OFP_IOC_IN)

#define	_OFP_IOC(inout,group,num,len)	\
	((unsigned long)((inout) | (((len) & OFP_IOCPARM_MASK) << 16) | ((group) << 8) | (num)))
#define	_OFP_IO(g,n)	_OFP_IOC(OFP_IOC_VOID,	(g), (n), 0)
#define	_OFP_IOWINT(g,n)	_OFP_IOC(OFP_IOC_VOID,	(g), (n), sizeof(int))
#define	_OFP_IOR(g,n,t)	_OFP_IOC(OFP_IOC_OUT,	(g), (n), sizeof(t))
#define	_OFP_IOW(g,n,t)	_OFP_IOC(OFP_IOC_IN,	(g), (n), sizeof(t))
/* this should be _IORW, but stdio got there first */
#define	_OFP_IOWR(g,n,t)	_OFP_IOC(OFP_IOC_INOUT,	(g), (n), sizeof(t))

#define	OFP_FIONREAD		 _OFP_IOR('f', 127, int)			/* get # bytes to read */
#define	OFP_FIONBIO		 _OFP_IOW('f', 126, int)			/* set/clear non-blocking i/o */
#define	OFP_FIOASYNC		 _OFP_IOW('f', 125, int)			/* set/clear async i/o */
#define	OFP_FIONWRITE		 _OFP_IOR('f', 119, int)			/* get # bytes (yet) to write */
#define	OFP_FIONSPACE		 _OFP_IOR('f', 118, int)			/* get space in send queue */

#define	OFP_SIOCATMARK	 _OFP_IOR('s',  7, int)			/* at oob mark? */

#define	OFP_SIOCADDRT	 	 _OFP_IOW('r', 10, struct ofp_rtentry)	/* add route */
#define	OFP_SIOCDELRT	 	 _OFP_IOW('r', 11, struct ofp_rtentry)	/* delete route */

#define	OFP_SIOCSIFADDR	 _OFP_IOW('i', 12, struct ofp_ifreq)	/* set ifnet address */
#define	OFP_SIOCGIFADDR	_OFP_IOWR('i', 33, struct ofp_ifreq)	/* get ifnet address */
#define	OFP_SIOCSIFDSTADDR	 _OFP_IOW('i', 14, struct ofp_ifreq)	/* set p-p address */
#define	OFP_SIOCGIFDSTADDR	_OFP_IOWR('i', 34, struct ofp_ifreq)	/* get p-p address */
#define	OFP_OSIOCGIFBRDADDR	_OFP_IOWR('i', 18, struct ofp_ifreq)	/* get broadcast addr */
#define	OFP_SIOCGIFBRDADDR	_OFP_IOWR('i', 35, struct ofp_ifreq)	/* get broadcast addr */
#define	OFP_SIOCSIFBRDADDR	 _OFP_IOW('i', 19, struct ofp_ifreq)	/* set broadcast addr */
#define	OFP_OSIOCGIFCONF	_OFP_IOWR('i', 20, struct ofp_ifconf)	/* get ifnet list */
#define	OFP_SIOCGIFCONF	_OFP_IOWR('i', 36, struct ofp_ifconf)	/* get ifnet list */
#define	OFP_SIOCGIFNETMASK	_OFP_IOWR('i', 37, struct ofp_ifreq)	/* get net addr mask */
#define	OFP_SIOCSIFNETMASK	 _OFP_IOW('i', 22, struct ofp_ifreq)	/* set net addr mask */
#define	OFP_SIOCDIFADDR	 _OFP_IOW('i', 25, struct ofp_ifreq)	/* delete IF addr */
#define	OFP_SIOCAIFADDR	 _OFP_IOW('i', 26, struct ofp_ifaliasreq)	/* add/chg IF alias */
#define	OFP_SIOCALIFADDR	 _OFP_IOW('i', 27, struct ofp_if_laddrreq)	/* add IF addr */
#define	OFP_SIOCGLIFADDR	_OFP_IOWR('i', 28, struct ofp_if_laddrreq)	/* get IF addr */
#define	OFP_SIOCDLIFADDR	 _OFP_IOW('i', 29, struct ofp_if_laddrreq)	/* delete IF addr */
#define	OFP_SIOCGIFFIB	_OFP_IOWR('i', 92, struct ofp_ifreq)	/* get IF fib */
#define	OFP_SIOCSIFFIB	 _OFP_IOW('i', 93, struct ofp_ifreq)	/* set IF fib */
#define	OFP_SIOCGIFVRF OFP_SIOCGIFFIB
#define	OFP_SIOCSIFVRF OFP_SIOCSIFFIB
#define	OFP_SIOCIFCREATE	_OFP_IOWR('i', 122, struct ofp_ifreq)	/* create clone if */
#define	OFP_SIOCIFCREATE2	_OFP_IOWR('i', 124, struct ofp_ifreq)	/* create clone if */
#define	OFP_SIOCIFDESTROY	 _OFP_IOW('i', 121, struct ofp_ifreq)	/* destroy clone if */
#define	OFP_SIOCIFGCLONERS	_OFP_IOWR('i', 120, struct ofp_if_clonereq) /* get cloners */
#define	OFP_SIOCGIFGMEMB	_OFP_IOWR('i', 138, struct ofp_ifgroupreq)	/* get members */
#define	OFP_SIOCSIFTUN	 _OFP_IOW('i', 139, struct ofp_in_tunreq)	/* set tunnel */
#define	OFP_SIOCGIFTUN	_OFP_IOWR('i', 140, struct ofp_in_tunreq)	/* get tunnel */

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* !_SYS_SOCKIO_H_ */
