/*
* (c) 2012 by Sasha Tolstykh <eviltau@gmail.com>
*
*/

#include <xtables.h>
#include <getopt.h>
#include <stdio.h>

#include "xt_wildcard.h"

static void wildcard_mt_help(void){
	printf("wildcard match options:\n"
		"[!] --ipsrc addr/wildcard\tMatch source address of packet\n"
		"[!] --ipdst addr/wildcard\tMatch destination address of packet\n");
}

static void wildcard_mt_init (struct xt_entry_match *match){
	printf("[xt_wildcard] Called wildcard_mt_init\n");
}

static int wildcard_mt_parse (int c, char **argv, int invert, unsigned int *flags, 
				const void *entry, struct xt_entry_match **match){
	struct xt_wildcard_mtinfo *info = (void *)(*match)->data;
        __u8 * ip_ptr, *wc_ptr;
	switch(c){
		case '1': /* ipsrc */
			if(*flags & XT_WILDCARD_SRC){
				xtables_error(PARAMETER_PROBLEM, "xt_wildcard: Only use \"%s\" once!", "--ipsrc");
			}
			*flags |= XT_WILDCARD_SRC;
			info->flags |= XT_WILDCARD_SRC;
			if(invert)
				info->flags |= XT_WILDCARD_SRC_INV;
                        ip_ptr = (void*)&info->src_ip;
                        wc_ptr = (void*)&info->src_wc;
                        
			if(sscanf(optarg,"%hhu.%hhu.%hhu.%hhu/%hhu.%hhu.%hhu.%hhu",
                                 ip_ptr,&ip_ptr[1],&ip_ptr[2],&ip_ptr[3],
                                 wc_ptr,&wc_ptr[1],&wc_ptr[2],&wc_ptr[3]
                                )!=8)
					xtables_error(PARAMETER_PROBLEM, "xt_wildcard: Can't parse string %s",optarg);
                        info->src_wc = ~(info->src_wc); /* invert wildcard */

                        if(((info->src_ip) & (info->src_wc)) != info->src_ip){
                            xtables_error(PARAMETER_PROBLEM, "xt_wildcard: Error in network address or wildcard mask %s:",optarg);
                        }
                   
                        
			break;
		case '2': /* ipdst */
			if(*flags & XT_WILDCARD_DST){
				xtables_error(PARAMETER_PROBLEM, "xt_wildcard: Only use \"%s\" once!", "--ipsrc");
			}
			*flags |= XT_WILDCARD_DST;
			info->flags |= XT_WILDCARD_DST;
			if(invert)
				info->flags |= XT_WILDCARD_DST_INV;
                        ip_ptr = (void*)&info->dst_ip;
                        wc_ptr = (void*)&info->dst_wc;
                        
			if(sscanf(optarg,"%hhu.%hhu.%hhu.%hhu/%hhu.%hhu.%hhu.%hhu",
                                 ip_ptr,&ip_ptr[1],&ip_ptr[2],&ip_ptr[3],
                                 wc_ptr,&wc_ptr[1],&wc_ptr[2],&wc_ptr[3]
                                )!=8)
					xtables_error(PARAMETER_PROBLEM, "xt_wildcard: Can't parse string %s",optarg);
                        info->dst_wc = ~(info->dst_wc); /* invert wildcard */

                        if(((info->dst_ip) & (info->dst_wc)) != info->dst_ip){
                            xtables_error(PARAMETER_PROBLEM, "xt_wildcard: Error in network address or wildcard mask %s:",optarg);
                        }
                   
                        
			break;

		default: xtables_error(PARAMETER_PROBLEM, "xt_wildcard: unknown param");
	};
	return true;
}


static void wildcard_mt_check (unsigned int flags){
	if(flags == 0){
		xtables_error(PARAMETER_PROBLEM,"xt_wildcard: You must specify parameters "
			"--ipsrc or --ipdst is required");
	}
}

static void wildcard_mt_print(const void *entry, const struct xt_entry_match *match, int numeric){
	const struct xt_wildcard_mtinfo * info = (const void*)match->data;
        __u8 * ip_ptr, *wc_ptr;
	if(info->flags & XT_WILDCARD_SRC){
		if(info->flags & XT_WILDCARD_SRC_INV)
			printf("not ");
                ip_ptr = (__u8*)&info->src_ip;
                wc_ptr = (__u8*)&info->src_wc;

                printf("src %hhu.%hhu.%hhu.%hhu/%hhu.%hhu.%hhu.%hhu ",
                         ip_ptr[0], ip_ptr[1], ip_ptr[2], ip_ptr[3],
                        ~wc_ptr[0],~wc_ptr[1],~wc_ptr[2],~wc_ptr[3]);
			
	}
	if(info->flags & XT_WILDCARD_DST){
                if(info->flags & XT_WILDCARD_SRC)
                        printf("and ");
                
                if(info->flags & XT_WILDCARD_DST_INV)
                        printf("not ");
                ip_ptr = (__u8*)&info->dst_ip;
                wc_ptr = (__u8*)&info->dst_wc;

                printf("dst %hhu.%hhu.%hhu.%hhu/%hhu.%hhu.%hhu.%hhu ",
                         ip_ptr[0], ip_ptr[1], ip_ptr[2], ip_ptr[3],
                        ~wc_ptr[0],~wc_ptr[1],~wc_ptr[2],~wc_ptr[3]);
        }
}

static void wildcard_mt_save(const void *entry, const struct xt_entry_match *match){
    const struct xt_wildcard_mtinfo * info = (const void*)match->data;
    __u8 *ip_ptr, *wc_ptr;
    
    if(info->flags & XT_WILDCARD_SRC){
		if(info->flags & XT_WILDCARD_SRC_INV)
			printf(" !");
                ip_ptr = (__u8*)&info->src_ip;
                wc_ptr = (__u8*)&info->src_wc;

		printf(" --ipsrc %hhu.%hhu.%hhu.%hhu/%hhu.%hhu.%hhu.%hhu",
                         ip_ptr[0], ip_ptr[1], ip_ptr[2], ip_ptr[3],
                        ~wc_ptr[0],~wc_ptr[1],~wc_ptr[2],~wc_ptr[3]);
			
        }
    if(info->flags & XT_WILDCARD_DST){
		if(info->flags & XT_WILDCARD_DST_INV)
			printf(" !");
                ip_ptr = (__u8*)&info->dst_ip;
                wc_ptr = (__u8*)&info->dst_wc;

                printf(" --ipdst %hhu.%hhu.%hhu.%hhu/%hhu.%hhu.%hhu.%hhu",
                         ip_ptr[0], ip_ptr[1], ip_ptr[2], ip_ptr[3],
                        ~wc_ptr[0],~wc_ptr[1],~wc_ptr[2],~wc_ptr[3]);

	}
}

static const struct option wildcard_mt_opts[] = {
	{.name = "ipsrc", .has_arg = true, .val = '1' },
	{.name = "ipdst", .has_arg = true, .val = '2' },
	XT_GETOPT_TABLEEND,
}; 

static struct xtables_match wildcard_mt_reg = {
	.name		= "wildcard", 
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct xt_wildcard_mtinfo)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_wildcard_mtinfo)),
	.help		= wildcard_mt_help,
	.init		= wildcard_mt_init,
	.parse		= wildcard_mt_parse,
	.final_check	= wildcard_mt_check,
	.print		= wildcard_mt_print,
	.save		= wildcard_mt_save, 
	.extra_opts	= wildcard_mt_opts
};

static __attribute__((constructor)) void wildcard_mt_ldr(void){
    xtables_register_match(&wildcard_mt_reg);
}
