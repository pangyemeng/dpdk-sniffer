#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_timer.h>

#include "../common/config.h"
#include "../flow/flow.h"
#include "capture.h"
#include "../dissector/packet.h"
#include "../dissector/dissector.h"

#ifndef APP_LCORE_IO_FLUSH
#define APP_LCORE_IO_FLUSH           1000000
#endif

#ifndef APP_LCORE_WORKER_FLUSH
#define APP_LCORE_WORKER_FLUSH       1000000
#endif

#ifndef APP_STATS
#define APP_STATS                    1000000
#endif

#define APP_IO_RX_DROP_ALL_PACKETS   0
#define APP_WORKER_DROP_ALL_PACKETS  0
#define APP_IO_TX_DROP_ALL_PACKETS   0

#ifndef APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH_ENABLE    1
#endif

#ifndef APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH_ENABLE   1
#endif

#ifndef APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH_ENABLE    1
#endif

#if APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH0(p)       rte_prefetch0(p)
#define APP_IO_RX_PREFETCH1(p)       rte_prefetch1(p)
#else
#define APP_IO_RX_PREFETCH0(p)
#define APP_IO_RX_PREFETCH1(p)
#endif

#if APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH0(p)      rte_prefetch0(p)
#define APP_WORKER_PREFETCH1(p)      rte_prefetch1(p)
#else
#define APP_WORKER_PREFETCH0(p)
#define APP_WORKER_PREFETCH1(p)
#endif

#if APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH0(p)       rte_prefetch0(p)
#define APP_IO_TX_PREFETCH1(p)       rte_prefetch1(p)
#else
#define APP_IO_TX_PREFETCH0(p)
#define APP_IO_TX_PREFETCH1(p)
#endif

static inline void app_lcore_io_rx_flush(struct app_lcore_params_io *lp)
{
	int ret;

	if (likely((lp->rx.mbuf_out_flush[0] == 0) ||
			(lp->rx.mbuf_out[0].n_mbufs == 0)))
	{
		lp->rx.mbuf_out_flush[0] = 1;
		return;
	}

	ret = rte_ring_sp_enqueue_bulk(lp->rx.rings[0], (void **) lp->rx.mbuf_out[0].array, lp->rx.mbuf_out[0].n_mbufs);

	if (unlikely(ret < 0))
	{
		uint32_t k;
		for (k = 0; k < lp->rx.mbuf_out[0].n_mbufs; k++)
		{
			struct rte_mbuf *pkt_to_free = lp->rx.mbuf_out[0].array[k];
			rte_pktmbuf_free(pkt_to_free);
		}
	}

	lp->rx.mbuf_out[0].n_mbufs = 0;
	lp->rx.mbuf_out_flush[0] = 1;
}

//从接收缓存中取出数据包放入流管理环形队列
static inline void app_lcore_io_rx_buffer_to_flow(struct app_lcore_params_io *lp, uint32_t flow_id, struct rte_mbuf *mbuf, uint32_t bsz)
{
	uint32_t pos;
	int ret;

	pos = lp->rx.mbuf_out[flow_id].n_mbufs;
	lp->rx.mbuf_out[flow_id].array[pos++] = mbuf;
	if (likely(pos < bsz))
	{
		lp->rx.mbuf_out[flow_id].n_mbufs = pos;
		return;
	}

	ret = rte_ring_sp_enqueue_bulk(lp->rx.rings[flow_id], (void **) lp->rx.mbuf_out[flow_id].array, bsz);

	if (unlikely(ret == -ENOBUFS))
	{
		uint32_t k;
		for (k = 0; k < bsz; k++)
		{
			struct rte_mbuf *m = lp->rx.mbuf_out[flow_id].array[k];
			rte_pktmbuf_free(m);
		}
	}

	lp->rx.mbuf_out[flow_id].n_mbufs = 0;
	lp->rx.mbuf_out_flush[flow_id] = 0;

#if APP_STATS
	lp->rx.rings_iters[flow_id]++;
	if (likely(ret == 0))
	{
		lp->rx.rings_count[flow_id]++;
	}
	if (unlikely(lp->rx.rings_iters[flow_id] == APP_STATS))
	{
		unsigned lcore = rte_lcore_id();

		printf("\tI/O RX %u out (worker %u): enq success rate = %.2f\n", lcore, (unsigned) flow_id, ((double) lp->rx.rings_count[flow_id]) / ((double) lp->rx.rings_iters[flow_id]));
		lp->rx.rings_iters[flow_id] = 0;
		lp->rx.rings_count[flow_id] = 0;
	}
#endif
}

static inline void app_lcore_io_rx(struct app_lcore_params_io *lp, uint32_t bsz_rd, uint32_t bsz_wr)
{
	static long pkt_num = 0;
	uint32_t i;

	for (i = 0; i < lp->rx.n_nic_queues; i++)
	{
		uint8_t port = lp->rx.nic_queues[i].port;
		uint8_t queue = lp->rx.nic_queues[i].queue;
		uint32_t n_mbufs, j;

		n_mbufs = rte_eth_rx_burst(port, queue, lp->rx.mbuf_in.array, (uint16_t) bsz_rd);

		if (unlikely(n_mbufs == 0))
		{
			continue;
		}
		//将包放入环形队列
		for (j = 0; j < n_mbufs; j ++)
		{
			struct rte_mbuf *pkt = lp->rx.mbuf_in.array[j];
			app_lcore_io_rx_buffer_to_flow(lp, 0, pkt, bsz_wr);
		}

#if APP_STATS
		lp->rx.nic_queues_iters[i]++;
		lp->rx.nic_queues_count[i] += n_mbufs;
		if (unlikely(lp->rx.nic_queues_iters[i] == APP_STATS))
		{
			struct rte_eth_stats stats;
			unsigned lcore = rte_lcore_id();

			rte_eth_stats_get(port, &stats);

			printf("I/O RX %u in (NIC port %u): NIC drop ratio = %.2f avg burst size = %.2f\n", lcore, (unsigned) port, (double) stats.imissed / (double) (stats.imissed + stats.ipackets),
					((double) lp->rx.nic_queues_count[i]) / ((double) lp->rx.nic_queues_iters[i]));
			lp->rx.nic_queues_iters[i] = 0;
			lp->rx.nic_queues_count[i] = 0;
		}
#endif


#if APP_IO_RX_DROP_ALL_PACKETS
		for (j = 0; j < n_mbufs; j ++)
		{
			struct rte_mbuf *pkt = lp->rx.mbuf_in.array[j];
			rte_pktmbuf_free(pkt);
		}

		continue;
#endif


#if 0
		//此处对数据包进行解包
		packet_t pkt;
		ipv4_flow_t *flow;
		for (j = 0; j < n_mbufs; j++)
		{
			struct rte_mbuf *mbuf = lp->rx.mbuf_in.array[j];
			if (dissect_packet(mbuf, &pkt))
			{
				flow_para_t para;
				create_flow_para(pkt.ip_hdr, &para);
				//暂紧考虑TCP协议
				if (para.proto == IPPROTO_TCP)
				{
					pkt_num++;
					flow = create_flow_ipv4(rte_socket_id(), &para, mbuf);
					printf("flow:"
							"\n flow length:  %d"
							"\n ipv4_5tupl %u %u %u %u %u \n", flow->pkt_num, flow->sip, flow->dip, flow->sport, flow->dport, flow->proto);
				}
			}
		}
#endif
	}

}

//仅捕获包 嗅探设备无转发包
void app_lcore_main_loop_io(void)
{
	uint32_t lcore = rte_lcore_id();
	struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
	uint64_t i = 0;

	uint32_t bsz_rx_rd = app.burst_size_io_rx_read;
	uint32_t bsz_rx_wr = app.burst_size_io_rx_write;

	for (;;)
	{
		if (APP_LCORE_IO_FLUSH && (unlikely(i == APP_LCORE_IO_FLUSH)))
		{
			if (likely(lp->rx.n_nic_queues > 0))
			{
				app_lcore_io_rx_flush(lp);
			}
			i = 0;
		}

		if (likely(lp->rx.n_nic_queues > 0))
		{
			app_lcore_io_rx(lp, bsz_rx_rd, bsz_rx_wr);
		}
		i++;
	}
}
