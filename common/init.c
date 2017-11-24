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
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>

#include "init.h"
#include "config.h"
#include "flow.h"

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
};

int app_is_socket_used(uint32_t socket)
{
	uint32_t lcore;

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type == e_APP_LCORE_DISABLED) {
			continue;
		}

		if (socket == rte_lcore_to_socket_id(lcore)) {
			return 1;
		}
	}

	return 0;
}

uint32_t app_get_lcores_flow(void)
{
	uint32_t lcore, count;

	count = 0;
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type != e_APP_LCORE_FLOW) {
			continue;
		}

		count ++;
	}

	if (count > APP_MAX_FLOW_LCORES) {
		rte_panic("Algorithmic error (too many flow lcores)\n");
		return 0;
	}

	return count;
}

uint32_t app_get_lcores_io_rx(void)
{
	uint32_t lcore, count;

	count = 0;
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->rx.n_nic_queues == 0)) {
			continue;
		}
		count ++;
	}

	return count;
}

static void app_init_mbuf_pools(void)
{
	unsigned socket, lcore;

	/* Init the buffer pools */
	for (socket = 0; socket < APP_MAX_SOCKETS; socket ++) {
		char name[32];
		if (app_is_socket_used(socket) == 0) {
			continue;
		}

		snprintf(name, sizeof(name), "mbuf_pool_%u", socket);
		printf("Creating the mbuf pool for socket %u ...\n", socket);
		app.pools[socket] = rte_pktmbuf_pool_create(
			name, APP_DEFAULT_MEMPOOL_BUFFERS,
			APP_DEFAULT_MEMPOOL_CACHE_SIZE,
			0, APP_DEFAULT_MBUF_DATA_SIZE, socket);
		if (app.pools[socket] == NULL) {
			rte_panic("Cannot create mbuf pool on socket %u\n", socket);
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type == e_APP_LCORE_DISABLED) {
			continue;
		}

		socket = rte_lcore_to_socket_id(lcore);
		app.lcore_params[lcore].pool = app.pools[socket];
	}
}

static void app_init_rings_rx(void)
{
	unsigned lcore;

	/* Initialize the rings for the RX side */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;
		unsigned socket_io, lcore_flow;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->rx.n_nic_queues == 0)) {
			continue;
		}

		socket_io = rte_lcore_to_socket_id(lcore);

		for (lcore_flow = 0; lcore_flow < APP_MAX_LCORES; lcore_flow ++) {
			char name[32];
			struct app_lcore_params_flow *lp_flow = &app.lcore_params[lcore_flow].flow;
			struct rte_ring *ring = NULL;

			if (app.lcore_params[lcore_flow].type != e_APP_LCORE_FLOW) {
				continue;
			}

			printf("Creating ring to connect I/O lcore %u (socket %u) with flow lcore %u ...\n",
				lcore,
				socket_io,
				lcore_flow);
			snprintf(name, sizeof(name), "app_ring_rx_s%u_io%u_flow%u",
				socket_io,
				lcore,
				lcore_flow);
			ring = rte_ring_create(
				name,
				app.ring_rx_size,
				socket_io,
				RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_panic("Cannot create ring to connect I/O core %u with flow core %u\n",
					lcore,
					lcore_flow);
			}

			lp_io->rx.rings[lp_io->rx.n_rings] = ring;
			lp_io->rx.n_rings ++;

			lp_flow->rings_in[lp_flow->n_rings_in] = ring;
			lp_flow->n_rings_in ++;
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->rx.n_nic_queues == 0)) {
			continue;
		}

		if (lp_io->rx.n_rings != app_get_lcores_flow()) {
			rte_panic("Algorithmic error (I/O RX rings)\n");
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_flow *lp_flow = &app.lcore_params[lcore].flow;

		if (app.lcore_params[lcore].type != e_APP_LCORE_FLOW) {
			continue;
		}

		if (lp_flow->n_rings_in != app_get_lcores_io_rx()) {
			rte_panic("Algorithmic error (worker input rings)\n");
		}
	}
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint32_t n_rx_queues, n_tx_queues;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			n_rx_queues = app_get_nic_rx_queues_per_port(portid);
			if (n_rx_queues == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
							(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void app_init_nics(void)
{
	unsigned socket;
	uint32_t lcore;
	uint8_t port, queue;
	int ret;
	uint32_t n_rx_queues , n_tx_queues = 0;

	/* Init NIC ports and queues, then start the ports */
	for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
		struct rte_mempool *pool;

		n_rx_queues = app_get_nic_rx_queues_per_port(port);

		if (n_rx_queues == 0) {
			continue;
		}

		/* Init port */
		printf("Initializing NIC port %u ...\n", (unsigned) port);
		ret = rte_eth_dev_configure(
			port,
			(uint8_t) n_rx_queues,
			(uint8_t) n_tx_queues,
			&port_conf);
		if (ret < 0) {
			rte_panic("Cannot init NIC port %u (%d)\n", (unsigned) port, ret);
		}
		rte_eth_promiscuous_enable(port);

		/* Init RX queues */
		for (queue = 0; queue < APP_MAX_RX_QUEUES_PER_NIC_PORT; queue ++) {
			if (app.nic_rx_queue_mask[port][queue] == 0) {
				continue;
			}

			app_get_lcore_for_nic_rx(port, queue, &lcore);
			socket = rte_lcore_to_socket_id(lcore);
			pool = app.lcore_params[lcore].pool;

			printf("Initializing NIC port %u RX queue %u ...\n",
				(unsigned) port,
				(unsigned) queue);
			ret = rte_eth_rx_queue_setup(
				port,
				queue,
				(uint16_t) app.nic_rx_ring_size,
				socket,
				NULL,
				pool);
			if (ret < 0) {
				rte_panic("Cannot init RX queue %u for port %u (%d)\n",
					(unsigned) queue,
					(unsigned) port,
					ret);
			}
		}
		/* Start port */
		ret = rte_eth_dev_start(port);
		if (ret < 0) {
			rte_panic("Cannot start port %d (%d)\n", port, ret);
		}
	}

	check_all_ports_link_status(APP_MAX_NIC_PORTS, (~0x0));
}

void app_init(void)
{
	app_init_mbuf_pools();
	app_init_rings_rx();
	//创建流表
	create_flowtab(rte_socket_id());
	app_init_nics();
	printf("Initialization completed.\n");
}
