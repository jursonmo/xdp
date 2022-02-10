// +build ignore
//https://elixir.bootlin.com/linux/v5.4.170/source/samples/bpf/xdp_redirect_map_kern.c
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define MAX_SOCKS 64
#define MAX_PORT 512

static volatile unsigned const char PROTO;
static volatile unsigned const char PROTO = IPPROTO_ICMP;

//Ensure map references are available.
/*
        These will be initiated from go and 
        referenced in the end BPF opcodes by file descriptor
*/

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = MAX_SOCKS,
};

struct bpf_map_def SEC("maps") qidconf_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = MAX_SOCKS,
};

struct l2fwd_entry {
    int outif;
    unsigned char dstmac[6];
};

//key:__u32 dstip, value: struct l2fwd_entry
struct bpf_map_def SEC("maps") l2fwd_map = {
	//.type = BPF_MAP_TYPE_ARRAY,
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct l2fwd_entry),
	.max_entries = MAX_SOCKS,
};

struct bpf_map_def SEC("maps") txport_map = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = MAX_PORT,
};

/* Redirect require an XDP bpf_prog loaded on the TX device */
SEC("xdp_redirect_dummy")
int xdp_redirect_dummy_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp_connect") int xdp_redirect(struct xdp_md *ctx)
{
    return bpf_redirect_map(&txport_map, ctx->ingress_ifindex, 0);
}

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
    struct l2fwd_entry *l2fwd_entry;
    int *txport, ret;
	int *qidconf, index = ctx->rx_queue_index;

	// bpf_printk("PROTO:%d, ctx->ingress_ifindex:%d\n", PROTO, ctx->ingress_ifindex);
	// return bpf_redirect_map(&txport_map, ctx->ingress_ifindex, 0);

	// A set entry here means that the correspnding queue_id
	// has an active AF_XDP socket bound to it.
	qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf)
		return XDP_PASS;
	
	// redirect packets to an xdp socket that match the given IPv4 or IPv6 protocol; pass all other packets to the kernel
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 h_proto = eth->h_proto;
	if ((void*)eth + sizeof(*eth) <= data_end) {
		if (bpf_htons(h_proto) == ETH_P_IP) {
			struct iphdr *ip = data + sizeof(*eth);         
			if ((void*)ip + sizeof(*ip) <= data_end) {//必须先判断这句，不然使用ip->daddr报错:offset is outside of the packet
				/*; l2fwd_entry = bpf_map_lookup_elem(&l2fwd_map, &ip->daddr);
					23: (bf) r2 = r9
					24: (07) r2 += 30
					; l2fwd_entry = bpf_map_lookup_elem(&l2fwd_map, &ip->daddr);
					25: (18) r1 = 0xffff88f6785b3000
					27: (85) call bpf_map_lookup_elem#1
					invalid access to packet, off=30 size=4, R2(id=0,off=30,r=14)
					R2 offset is outside of the packet
				*/
				//try to use fast path
				l2fwd_entry = bpf_map_lookup_elem(&l2fwd_map, &ip->daddr);
				bpf_printk("ip->daddr:%d\\n", ip->daddr);
				if (l2fwd_entry){
					txport = bpf_map_lookup_elem(&txport_map, &l2fwd_entry->outif);
					bpf_printk("l2fwd_entry->outif:%d, dstmac[0]:%d,%d\\n", l2fwd_entry->outif,l2fwd_entry->dstmac[0], l2fwd_entry->dstmac[5] );
					if (txport){
						/* update dst mac*/
						unsigned char *p = data;
						p[0] = l2fwd_entry->dstmac[0];
						p[1] = l2fwd_entry->dstmac[1];
						p[2] = l2fwd_entry->dstmac[2];
						p[3] = l2fwd_entry->dstmac[3];
						p[4] = l2fwd_entry->dstmac[4];
						p[5] = l2fwd_entry->dstmac[5];
						bpf_printk("chang mac key *txport:%d, ingress_ifindex:%d\n",  *txport, ctx->ingress_ifindex);
						//bpf_printk("no chang mac key *txport:%d, ingress_ifindex:%d\n",  *txport, ctx->ingress_ifindex);
						/* send packet out physical port */
						ret = bpf_redirect_map(&txport_map, *txport, 0);
						//ret = bpf_redirect_map(&txport_map, ctx->ingress_ifindex, 0);
						bpf_printk("XDP_REDIRECT:%d, ret:%d\n", XDP_REDIRECT, ret);
						return ret;
					}
				}

				if (ip->protocol == PROTO) {
					if (*qidconf)
						return bpf_redirect_map(&xsks_map, index, 0);
				}
			}
		} else if (bpf_htons(h_proto) == ETH_P_IPV6) {
			struct ipv6hdr *ip = data + sizeof(*eth);
			if ((void*)ip + sizeof(*ip) <= data_end) {
				if (ip->nexthdr == PROTO) {
					if (*qidconf)
						return bpf_redirect_map(&xsks_map, index, 0);
				}
			}
		}
	}

	return XDP_PASS;
}

//Basic license just for compiling the object code
//char __license[] SEC("license") = "LGPL-2.1 or BSD-2-Clause";
//45: (85) call bpf_trace_printk#6
//cannot call GPL-restricted function from non-GPL compatible program
//使用 bpf_trace_printk() 的 BPF 程序必须具有 GPL 兼容的许可证。 
//对于基于 libbpf 的 BPF 应用程序，这意味着使用特殊变量指定许可证：
char __license[] SEC("license") = "GPL";