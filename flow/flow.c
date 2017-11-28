#include <stdint.h>
#include <stdio.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>

#include "../common/common.h"
#include "../common/config.h"
#include "../dissector/packet.h"
#include "../dissector/dissector.h"


#include "flow.h"

#define NB_SOCKETS 8
#define FLOW_HASH_ENTRIES	1024

#define PACKET_NUM  1024*1024
#define PACKET_SIZE (sizeof(packet_t))

#define IPV4_FLOW_ENTRIES  1024
#define IPV4_FLOW_SIZE (sizeof(ipv4_flow_t))

typedef struct rte_hash lookup_struct_t;
static lookup_struct_t *flow_lookup_struct[NB_SOCKETS];

struct rte_mempool * ipv4_flow_pool = NULL;
struct rte_mempool * packet_pool = NULL;

#define DEFAULT_HASH_FUNC       rte_hash_crc


/* Per-port statistics struct */
struct flow_statistics {
	uint64_t rx;
	uint64_t flow_num;
} __rte_cache_aligned;
struct flow_statistics flow_stat;

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */

static void ipv4_flow_obj_init(struct rte_mempool *mp, __attribute__((unused)) void *arg, void *obj, unsigned i)
{
	ipv4_flow_t * flow = (ipv4_flow_t *) obj;
	memset(flow, 0, mp->elt_size);
}

static void packet_obj_init(struct rte_mempool *mp, __attribute__((unused)) void *arg, void *obj, unsigned i)
{
	packet_t * pkt = (packet_t *) obj;
	memset(pkt, 0, mp->elt_size);
}

//DPDK在我这个场景暂时没找到好的hash算法，现在简单用一个五元组相加。
static inline uint32_t ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
	const struct ipv4_5tuple *k;

	k = data;

	init_val = k->ip_dst + k->ip_src + k->port_dst + k->port_src;

	return init_val;
}

//暂时用默认参数，后期再根据需求做相关变化
int create_flowtab(int socketid)
{
	//做流判断的hash表
	struct rte_hash_parameters flow_hash_params = { .name = NULL, .entries = FLOW_HASH_ENTRIES, .key_len = sizeof(struct ipv4_5tuple), .hash_func = ipv4_hash_crc, .hash_func_init_val = 0, };

	unsigned i;
	int ret;
	char s[64];


	/* 创建流hash表 */
	snprintf(s, sizeof(s), "flowtab_hash_%d", socketid);
	flow_hash_params.name = s;
	flow_hash_params.socket_id = socketid;
	flow_lookup_struct[socketid] = rte_hash_create(&flow_hash_params);

	if (flow_lookup_struct[socketid] == NULL)
	{
		rte_exit(EXIT_FAILURE, "Unable to create the flowtab hash on socket %d\n", socketid);
	}

	/* 为包创建内存池 ,为包结构分配内存  */
	packet_pool = rte_mempool_create("packet_pool",
	PACKET_NUM, PACKET_SIZE, 0, 0, NULL, NULL, packet_obj_init, NULL, socketid, 0);
	if (packet_pool == NULL) rte_exit(EXIT_FAILURE, "Create packet_pool mempool failed\n");
	//	rte_mempool_dump(stdout, packet_pool);

	/* 为流结构创建内存池 ,为流结构分配内存  */
	ipv4_flow_pool = rte_mempool_create("ipv4_flow_pool", IPV4_FLOW_ENTRIES, IPV4_FLOW_SIZE, 0, 0, NULL, NULL, ipv4_flow_obj_init, NULL, socketid, 0);
	if (ipv4_flow_pool == NULL) rte_exit(EXIT_FAILURE, "Create ipv4_flow_pool mempool failed\n");
	//	rte_mempool_dump(stdout, ipv4_flow_pool);

	//初始化打印流的定时器
	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	return socketid;
}

void delete_flowtab(int socketid)
{

}

int get_flowtab_stat(int socketid, flow_tab_t *flow_tab)
{

	return 0;
}

void create_flow_para(struct ipv4_hdr *ipv4_hdr, flow_para_t *para)
{
	struct tcp_hdr *tcp;
	struct udp_hdr *udp;
	int ret = 0;

	para->dip_v4 = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	para->sip_v4 = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	para->proto = ipv4_hdr->next_proto_id;

	switch (ipv4_hdr->next_proto_id)
	{
		case IPPROTO_TCP:
			tcp = (struct tcp_hdr *) ((unsigned char *) ipv4_hdr + sizeof(struct ipv4_hdr));
			para->dport = rte_be_to_cpu_16(tcp->dst_port);
			para->sport = rte_be_to_cpu_16(tcp->src_port);
			para->type = IPPROTO_TCP;
			break;

		case IPPROTO_UDP:
			udp = (struct udp_hdr *) ((unsigned char *) ipv4_hdr + sizeof(struct ipv4_hdr));
			para->dport = rte_be_to_cpu_16(udp->dst_port);
			para->sport = rte_be_to_cpu_16(udp->src_port);
			para->type = IPPROTO_UDP;
			break;

		default:
			para->dport = 0;
			para->dport = 0;
			break;
	}
}

/*大于  0 表示流创建成功
 *返回 -1 表示参数无效
 *返回  -2 表示空间不足
 *返回  0 表示流已存在
 * */
ipv4_flow_t * create_flow_ipv4(int socketid, flow_para_t *para, struct rte_mbuf *mbuf)
{
	int ret;
	ipv4_flow_t *flow = NULL;
	void *flow_tmp;
	void *pkt_tmp;
	void *ret_data;


	//根据para 提取5元组作为key
	struct ipv4_5tuple key;
	key.ip_dst = para->dip_v4;
	key.ip_src = para->sip_v4;
	key.port_dst = para->dport;
	key.port_src = para->sport;
	key.proto = para->proto;


	//	printf("key: %u %u %u %u %u \n", key.ip_dst, key.ip_src, key.port_dst, key.port_src, key.proto);

	//查找流是否存在
	ret = rte_hash_lookup(flow_lookup_struct[socketid], (const void *) &key);
	if (ret >= 0)
	{
		//根据5元组key查到对应的数据
		ret = rte_hash_lookup_data(flow_lookup_struct[socketid], &key, &ret_data);
		if (ret < 0)
		{
			printf("rte_hash_lookup_data error\n");
			return -1;
		}
		flow = (ipv4_flow_t *) ret_data;
		flow->state = FLOW_EXIST;
		flow->pkt_num++;
		//从内存池中分配一个包的空间
		if (rte_mempool_get(packet_pool, &pkt_tmp) < 0)
		{
			printf("Error to get flowtab_pool buffer\n");
			return NULL;
		}
		packet_t *pkt = (packet_t *) pkt_tmp;
		pkt->ehdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr* );
		pkt->ip_hdr = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));
		pkt->tcp_hdr = (struct tcp_hdr *) ((unsigned char *) pkt->ip_hdr + sizeof(struct ipv4_hdr));
		pkt->mbuf = mbuf;
		pkt->next = NULL;

		flow->last_pkt->next = pkt;
		flow->last_pkt = pkt;
		return flow;
	}
	//从内存池中分配一个包的空间
	if (rte_mempool_get(packet_pool, &pkt_tmp) < 0)
	{
		printf("Error to get flowtab_pool buffer\n");
		return NULL;
	}
	packet_t *pkt = (packet_t *) pkt_tmp;
	pkt->ehdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr* );
	pkt->ip_hdr = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));
	pkt->tcp_hdr = (struct tcp_hdr *) ((unsigned char *) pkt->ip_hdr + sizeof(struct ipv4_hdr));
	pkt->mbuf = mbuf;
	pkt->next = NULL;

	if (rte_mempool_get(ipv4_flow_pool, &flow_tmp) < 0)
	{
		printf("Error to get flowtab_pool buffer\n");
		return NULL;
	}
	flow = (ipv4_flow_t *) flow_tmp;

	flow->state = FLOW_NEW;
	flow->dip = para->dip_v4;
	flow->sip = para->sip_v4;
	flow->dport = para->dport;
	flow->sport = para->sport;
	flow->state = 1;
	flow->proto = para->proto;
	flow->tabid = ret;
	flow->appid = 0x0001; //后期完善,可以按端口做一个协议分类
	flow->pkt_num++;
	flow->pkt_queue = flow->pkt_queue_head = flow->last_pkt = pkt;


	//新建一条流：将key/flow放入hash表
	//step: 1
	ret = rte_hash_add_key_data(flow_lookup_struct[socketid], &key, (void *) flow);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE, "Unable to add entry to the"
			"flow hash on socket %d, return error -EINVAL\n", socketid);
	}
	return flow;
}

ipv4_flow_t *search_flow_ipv4(int socketid, flow_para_t *para)
{
	int ret;
	void *ret_data;
	ipv4_flow_t *flow;


	//根据para 提取5元组作为key
	struct ipv4_5tuple key;
	key.ip_dst = para->dip_v4;
	key.ip_src = para->sip_v4;
	key.port_dst = para->dport;
	key.port_src = para->sport;
	key.proto = para->proto;

	ret = rte_hash_lookup(flow_lookup_struct[socketid], (const void *) &key);
	if (ret >= 0)
	{
		//从桶第一个位置返ipv4流
		ret = rte_hash_lookup_data(flow_lookup_struct[socketid], &key, &ret_data);
		if (ret < 0)
		{
			printf("rte_hash_lookup_data error\n");
			return -1;
		}
		flow = (ipv4_flow_t *) ret_data;
		flow->state = FLOW_EXIST;
		return flow;
	}
	return NULL;
}

void del_flow_ipv4(int socketid, flow_para_t *para)
{
	int ret;
	//根据para 提取5元组作为key
	struct ipv4_5tuple key;
	key.ip_dst = para->dip_v4;
	key.ip_src = para->sip_v4;
	key.port_dst = para->dport;
	key.port_src = para->sport;
	key.proto = para->proto;
	rte_hash_del_key(flow_lookup_struct[socketid], (const void *) &key);
}

void print_flow_tab_info(int socketid)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;
	struct ipv4_5tuple *key;
	ipv4_flow_t *flow;

	while (rte_hash_iterate(flow_lookup_struct[socketid], &next_key, &next_data, &iter) >= 0)
	{
		key = (struct ipv4_5tuple *) next_key;
		if (key != NULL)
		{
			printf("key: %u %u %u %u %u \n", key->ip_dst, key->ip_src, key->port_dst, key->port_src, key->proto);
		}
		flow = (ipv4_flow_t *) next_data;
		if (flow != NULL)
		{
			printf("flow: %u %u %u %u %u \n", flow->sip, flow->dip, flow->sport, flow->dport, flow->proto);
		}
	}
}

void app_lcore_flow(struct app_lcore_params_flow *lp, uint32_t bsz_rd)
{
	uint32_t i;

	for (i = 0; i < lp->n_rings_in; i++)
	{
		struct rte_ring *ring_in = lp->rings_in[i];
		uint32_t j;
		int ret;
		ret = rte_ring_sc_dequeue_bulk(ring_in, (void **) lp->mbuf_in.array, bsz_rd);

		if (unlikely(ret == -ENOENT))
		{
			continue;
		}

		for (j = 0; j < bsz_rd; j++)
		{
			struct rte_mbuf *mbuf = lp->mbuf_in.array[j];
			ipv4_flow_t *flow;
			//目前流位两个方向
			packet_t pkt;
			if (dissect_packet(mbuf, &pkt))
			{
				flow_para_t para;
				create_flow_para(pkt.ip_hdr, &para);
				//暂紧考虑TCP协议
				if (para.proto == IPPROTO_TCP)
				{
					flow = create_flow_ipv4(rte_socket_id(), &para, mbuf);
					if(flow->state == FLOW_NEW)
					{
						flow_stat.flow_num++;
						printf("ipv4 flow: %u %u %u %u %u \n", flow->pkt_num, flow->sip, flow->dip, flow->sport, flow->dport, flow->proto);
					}
				}
			}
		}
		flow_stat.rx += bsz_rd;
	}
}

//对tcp流进行管理
void app_lcore_main_loop_flow(void)
{
	uint32_t lcore = rte_lcore_id();
	struct app_lcore_params_flow *lp = &app.lcore_params[lcore].flow;
	uint64_t i = 0;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	uint32_t bsz_rd = app.burst_size_flow_read;

	prev_tsc = 0;
	timer_tsc = 0;

	for (;;)
	{
		cur_tsc = rte_rdtsc();

		diff_tsc = cur_tsc - prev_tsc;

		/* if timer is enabled */
		if (timer_period > 0) {

			/* advance the timer */
			timer_tsc += diff_tsc;

			/* if timer has reached its timeout */
			if (unlikely(timer_tsc >= timer_period)) {

				/* do this only on master core */
					printf("flow info : rx %lu flow_num %lu\n", flow_stat.rx, flow_stat.flow_num);
					/* reset the timer */
					timer_tsc = 0;
			}

		}
		prev_tsc = cur_tsc;

		app_lcore_flow(lp, bsz_rd);
		i++;
	}
}

