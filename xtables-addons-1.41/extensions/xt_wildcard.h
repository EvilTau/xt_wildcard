#ifndef _LINUX_NETFILTER_XT_WILDCARD_H
#define _LINUX_NETFILTER_XT_WILDCARD_H 1

enum {
	XT_WILDCARD_SRC	= 1 << 0,
	XT_WILDCARD_DST = 1 << 1,
	XT_WILDCARD_SRC_INV = 1 << 2,
	XT_WILDCARD_DST_INV = 1 << 3,
};

struct xt_wildcard_mtinfo {
	__be32 src_ip, dst_ip; /* network address in be format */
        __be32 src_wc, dst_wc; /* inverted wildcard mask in be-format */

	__u8 flags;
};

#endif /* _LINUX_NETFILTER_XT_WILDCARD_H */

