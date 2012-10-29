/*
* (c) 2012 by Sasha Tolstykh <eviltau@gmail.com>
*/

#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include "xt_wildcard.h"

MODULE_AUTHOR("Sasha Tolstykh <eviltau@gmail.com>");
MODULE_DESCRIPTION("Xtables: wildcard match module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_wildcard");

static bool wildcard_mt(const struct sk_buff *skb, struct xt_action_param *par){
        const struct xt_wildcard_mtinfo *info = par->matchinfo;
        struct iphdr *header = ip_hdr(skb);
        bool rc = true;
        __be32 *src_wc = (__be32*)&info->src_wc;
        __be32 *src_ip = (__be32*)&info->src_ip;
        __be32 *dst_wc = (__be32*)&info->dst_wc;
        __be32 *dst_ip = (__be32*)&info->dst_ip;
        
        if(info->flags & XT_WILDCARD_SRC){
            rc = (header->saddr & *src_wc) == *src_ip ? true : false;
            if (info->flags & XT_WILDCARD_SRC_INV){
                rc = !rc;
            }
        }

        if(rc && info->flags & XT_WILDCARD_DST){
            rc = (header->daddr & *dst_wc) == *dst_ip ? true : false;
            if (info->flags & XT_WILDCARD_DST_INV)
                rc = !rc;
        }
	return rc;
}

static int wildcard_mt_check(const struct xt_mtchk_param *par){
	printk("(module)[xt_wildcard]: wildcard_mt_check\n");
	return 0;
}

static void wildcard_mt_destroy(const struct xt_mtdtor_param *par){
	printk("(module)[xt_wildcard]: wildcard_mt_destroy\n");
}

static struct xt_match wildcard_mt_reg __read_mostly = {
	.name		= "wildcard",
	.revision	= 0,
	.family		= NFPROTO_IPV4, 
	.match		= wildcard_mt,
	.checkentry	= wildcard_mt_check,
	.destroy	= wildcard_mt_destroy,
	.matchsize	= sizeof(struct xt_wildcard_mtinfo),
	.me		= THIS_MODULE
};

static int __init wildcard_mt_init(void){
	printk("(module)[xt_wildcard]: wildcard_mt_init\n");
	return xt_register_match(&wildcard_mt_reg);
}

static void __exit wildcard_mt_exit(void){
	printk("(module)[xt_wildcard]: wildcard_mt_exit\n");
	xt_unregister_match(&wildcard_mt_reg);
}

module_init(wildcard_mt_init);
module_exit(wildcard_mt_exit);

