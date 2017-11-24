#include <stdint.h>
#include <stdio.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>

#include "common.h"
#include "flow.h"

#define NB_SOCKETS 8
#define L3FWD_HASH_ENTRIES	1024

typedef struct rte_hash lookup_struct_t;
static lookup_struct_t *ipv4_l3fwd_lookup_struct[NB_SOCKETS];

#define DEFAULT_HASH_FUNC       rte_hash_crc

//暂时用默认参数，后期再根据需求做相关变化
int  create_flowtab(int socketid)
{
	struct rte_hash_parameters ipv4_l3fwd_hash_params = {
		.name = NULL,
		.entries = L3FWD_HASH_ENTRIES,
		.key_len = sizeof(struct ipv4_5tuple),
		.hash_func = DEFAULT_HASH_FUNC,
		.hash_func_init_val = 0,
	};

	unsigned i;
	int ret;
	char s[64];

	/* create ipv4 hash */
	snprintf(s, sizeof(s), "ipv4_l3fwd_hash_%d", socketid);
	ipv4_l3fwd_hash_params.name = s;
	ipv4_l3fwd_hash_params.socket_id = socketid;
	ipv4_l3fwd_lookup_struct[socketid] =
		rte_hash_create(&ipv4_l3fwd_hash_params);
	if (ipv4_l3fwd_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
				"socket %d\n", socketid);

	return socketid;
}


void  delete_flowtab(int socketid)
{


}


int get_flowtab_stat(int socketid, Flowtab_t *flow_tab)
{

	return 0;
}

void create_flow_key(struct ipv4_hdr *ipv4_hdr, struct ipv4_5tuple *key)
{
	struct tcp_hdr *tcp;
	struct udp_hdr *udp;
	int ret = 0;

	key->ip_dst = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	key->ip_src = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	key->proto = ipv4_hdr->next_proto_id;

	switch (ipv4_hdr->next_proto_id) {
		case IPPROTO_TCP:
			tcp = (struct tcp_hdr *)((unsigned char *)ipv4_hdr +
						sizeof(struct ipv4_hdr));
			key->port_dst = rte_be_to_cpu_16(tcp->dst_port);
			key->port_src = rte_be_to_cpu_16(tcp->src_port);
			break;

		case IPPROTO_UDP:
			udp = (struct udp_hdr *)((unsigned char *)ipv4_hdr +
						sizeof(struct ipv4_hdr));
			key->port_dst = rte_be_to_cpu_16(udp->dst_port);
			key->port_src = rte_be_to_cpu_16(udp->src_port);
			break;

		default:
			key->port_dst = 0;
			key->port_src = 0;
			break;
	}
}

/*大于  0 表示流创建成功
 *返回 -1 表示参数无效
 *返回  -2 表示空间不足
 *返回  0 表示流已存在
 * */
int create_flow_ipv4(int socketid, struct ipv4_5tuple *key)
{
	int ret;
	ret = rte_hash_lookup(ipv4_l3fwd_lookup_struct[socketid], (const void *)key);

	if(ret >= 0 )
	{
		return 0;
	}

	ret = rte_hash_add_key (ipv4_l3fwd_lookup_struct[socketid],
					(void *) key);
	if (ret == -EINVAL) {
		rte_exit(EXIT_FAILURE, "Unable to add entry to the"
			"flow hash on socket %d, return error -EINVAL\n", socketid);
	}
	if(ret == -ENOSPC){
		rte_exit(EXIT_FAILURE, "Unable to add entry to the"
				"flow hash on socket %d, return error -ENOSPC\n", socketid);
	}
	return ret;
}

IPv4Flow_t *search_flow_ipv4(int socketid,struct ipv4_5tuple key)
{
	return rte_hash_lookup(ipv4_l3fwd_lookup_struct[sockeid], (const void *)&key);
}

void  del_flow_ipv4(int socketid, struct ipv4_5tuple key)
{
	rte_hash_del_key(ipv4_l3fwd_lookup_struct[sockeid], (const void *)&key);
}
