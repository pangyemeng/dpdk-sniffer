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
#include <signal.h>

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
#include <rte_timer.h>

#include "common/common.h"
#include "common/config.h"
#include "common/init.h"
#include "capture/capture.h"

volatile bool force_quit;

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
	{
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

//每个逻辑核都做自己独立的活，下面主要分为三个线程，分别为收包、流管理、解析器
int app_lcore_main_loop(__attribute__((unused)) void *arg)
{
	struct app_lcore_params *lp;
	unsigned lcore;

	lcore = rte_lcore_id();
	lp = &app.lcore_params[lcore];

	//接收包
	if (lp->type == e_APP_LCORE_IO)
	{
		printf("Logical core %u (I/O) main loop.\n", lcore);
		app_lcore_main_loop_io();
	}

	//流管理
	if (lp->type == e_APP_LCORE_FLOW)
	{
		printf("Logical core %u (Flow Manage) main loop.\n", lcore);
		app_lcore_main_loop_flow();
	}

	//包解析器
	if (lp->type == e_APP_LCORE_DISSECTOR)
	{
		printf("Logical core %u (Dissector) main loop.\n", lcore);
	}
	return 0;
}

int main(int argc, char **argv)
{
	uint32_t lcore;
	int ret;

	printf("DPDK Sniffer ... ...\n");

	/* Initialise EAL*/
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
	}

	/* 初始化定时器库  */
	rte_timer_subsystem_init();

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	argc -= ret;
	argv += ret;

	/* Parse application arguments (after the EAL ones) */
	ret = app_parse_args(argc, argv);
	if (ret < 0)
	{
		app_print_usage();
		return -1;
	}
	//初始化内存池、环形缓冲、网卡
	app_init();

	/* 创建线程，在每个逻辑核 */
	rte_eal_mp_remote_launch(app_lcore_main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore)
	{
		if (rte_eal_wait_lcore(lcore) < 0)
		{
			return -1;
		}
	}
	return 0;
}

