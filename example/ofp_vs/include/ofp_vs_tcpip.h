#ifndef __OFP_VS_TCP_H__
#define __OFP_VS_TCP_H__

#include <asm/byteorder.h>
#include <rte_ip.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

/*
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__u16	check;
	__be32	saddr;
	__be32	daddr;
};
*/

struct __iphdr {
	uint8_t		ihl:4,
			version:4;
	uint8_t		tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
}__attribute__((__packed__));

/*
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__u16	check;
	__be16	urg_ptr;
};
*/

struct __tcphdr {
	uint16_t source;  /**< TCP source port. */
	uint16_t dest;  /**< TCP destination port. */
	uint32_t seq;  /**< TX data sequence number. */
	uint32_t ack_seq;  /**< RX data acknowledgement sequence number. */
    union {
        uint8_t  doff;  /**< Data offset. */
        struct {
            uint8_t rsvd:4,
                hlen:4;
        };
    };
    union {
        uint8_t  tcp_flags; /**< TCP flags */
        struct {
            uint8_t fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
        };
    };
	uint16_t window;    /**< RX flow control window. */
	uint16_t check;     /**< TCP checksum. */
	uint16_t urg_ptr;   /**< TCP urgent pointer, if any. */
} __attribute__((__packed__));


#define ip_hdr(__mbuf) \
	(struct iphdr *)(rte_pktmbuf_mtod(__mbuf, unsigned char *) + \
					sizeof(struct ether_hdr))

#define ip_hdrlen(__iphdr) \
	((__iphdr)->ihl << 2)
	//sizeof(struct ipv4_hdr)
	
#define tcp_hdr(iph) \
	(struct tcphdr *)((unsigned char *)(iph) + ip_hdrlen((iph)))
	

static inline uint16_t
ofp_vs_ipv4_udptcp_cksum(const struct iphdr *iphdr, const void *l4_hdr)
{
	uint32_t cksum;
	uint32_t l4_len;
	const struct ipv4_hdr *ipv4_hdr = (const struct ipv4_hdr *)iphdr;

	l4_len = rte_be_to_cpu_16(ipv4_hdr->total_length) - ip_hdrlen(iphdr);

	cksum = rte_raw_cksum(l4_hdr, l4_len);
	cksum += rte_ipv4_phdr_cksum(ipv4_hdr, 0);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;

	return cksum;
}

static inline uint16_t
ofp_vs_ipv4_cksum(const struct iphdr *iphdr)
{
	uint16_t cksum;
	cksum = rte_raw_cksum((const struct ipv4_hdr *)iphdr, ip_hdrlen(iphdr));
	return (cksum == 0xffff) ? cksum : ~cksum;
}

static inline int before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1 - seq2) < 0;
}

/*
 *	TCP option
 */
 
#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_MD5SIG         18

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED		12
#define TCPOLEN_WSCALE_ALIGNED		4
#define TCPOLEN_SACKPERM_ALIGNED	4
#define TCPOLEN_SACK_BASE		2
#define TCPOLEN_SACK_BASE_ALIGNED	4
#define TCPOLEN_SACK_PERBLOCK		8
#define TCPOLEN_MD5SIG_ALIGNED		20
#define TCPOLEN_MSS_ALIGNED		4

/* tcp flags */
#define TCPCB_FLAG_FIN          0x01
#define TCPCB_FLAG_SYN          0x02
#define TCPCB_FLAG_RST          0x04
#define TCPCB_FLAG_PSH          0x08
#define TCPCB_FLAG_ACK          0x10
#define TCPCB_FLAG_URG          0x20
#define TCPCB_FLAG_ECE          0x40
#define TCPCB_FLAG_CWR          0x80

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

#define IPTOS_TOS_MASK		0x1E
#define RT_TOS(tos)		((tos)&IPTOS_TOS_MASK)
#define IPDEFTTL        	64

#endif
