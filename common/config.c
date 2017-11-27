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
#include <rte_string_fns.h>
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
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "config.h"

struct app_params app;

static const char usage[] =
"                                                                               \n"
"    dpdk_sniffer <EAL PARAMS> -- <APP PARAMS>                                 \n"
"                                                                               \n"
"Application manadatory parameters:                                             \n"
"    --rx \"(PORT, QUEUE, LCORE), ...\" : List of NIC RX ports and queues       \n"
"           handled by the I/O RX lcores                                        \n"
"    --flow  \"LCORE, ...\" : List of the flow manage lcores 					\n";

static int str_to_unsigned_array(
	const char *s, size_t sbuflen,
	char separator,
	unsigned num_vals,
	unsigned *vals)
{
	char str[sbuflen+1];
	char *splits[num_vals];
	char *endptr = NULL;
	int i, num_splits = 0;

	/* copy s so we don't modify original string */
	snprintf(str, sizeof(str), "%s", s);
	num_splits = rte_strsplit(str, sizeof(str), splits, num_vals, separator);

	errno = 0;
	for (i = 0; i < num_splits; i++) {
		vals[i] = strtoul(splits[i], &endptr, 0);
		if (errno != 0 || *endptr != '\0')
			return -1;
	}

	return num_splits;
}

static int str_to_unsigned_vals(
	const char *s,
	size_t sbuflen,
	char separator,
	unsigned num_vals, ...)
{
	unsigned i, vals[num_vals];
	va_list ap;

	num_vals = str_to_unsigned_array(s, sbuflen, separator, num_vals, vals);

	va_start(ap, num_vals);
	for (i = 0; i < num_vals; i++) {
		unsigned *u = va_arg(ap, unsigned *);
		*u = vals[i];
	}
	va_end(ap);
	return num_vals;
}

#ifndef APP_ARG_RX_MAX_CHARS
#define APP_ARG_RX_MAX_CHARS     4096
#endif

#ifndef APP_ARG_RX_MAX_TUPLES
#define APP_ARG_RX_MAX_TUPLES    128
#endif

static int parse_arg_rx(const char *arg)
{
	const char *p0 = arg, *p = arg;
	uint32_t n_tuples;

	if (strnlen(arg, APP_ARG_RX_MAX_CHARS + 1) == APP_ARG_RX_MAX_CHARS + 1) {
		return -1;
	}

	n_tuples = 0;
	while ((p = strchr(p0,'(')) != NULL) {
		struct app_lcore_params *lp;
		uint32_t port, queue, lcore, i;

		p0 = strchr(p++, ')');
		if ((p0 == NULL) ||
		    (str_to_unsigned_vals(p, p0 - p, ',', 3, &port, &queue, &lcore) !=  3)) {
			return -2;
		}

		/* Enable port and queue for later initialization */
		if ((port >= APP_MAX_NIC_PORTS) || (queue >= APP_MAX_RX_QUEUES_PER_NIC_PORT)) {
			return -3;
		}
		if (app.nic_rx_queue_mask[port][queue] != 0) {
			return -4;
		}
		app.nic_rx_queue_mask[port][queue] = 1;

		/* Check and assign (port, queue) to I/O lcore */
		if (rte_lcore_is_enabled(lcore) == 0) {
			return -5;
		}

		if (lcore >= APP_MAX_LCORES) {
			return -6;
		}
		lp = &app.lcore_params[lcore];
		if (lp->type == e_APP_LCORE_FLOW || lp->type == e_APP_LCORE_DISSECTOR) {
			return -7;
		}
		lp->type = e_APP_LCORE_IO;
		const size_t n_queues = RTE_MIN(lp->io.rx.n_nic_queues,
		                                RTE_DIM(lp->io.rx.nic_queues));
		for (i = 0; i < n_queues; i ++) {
			if ((lp->io.rx.nic_queues[i].port == port) &&
			    (lp->io.rx.nic_queues[i].queue == queue)) {
				return -8;
			}
		}
		if (lp->io.rx.n_nic_queues >= APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE) {
			return -9;
		}
		lp->io.rx.nic_queues[lp->io.rx.n_nic_queues].port = (uint8_t) port;
		lp->io.rx.nic_queues[lp->io.rx.n_nic_queues].queue = (uint8_t) queue;
		lp->io.rx.n_nic_queues ++;

		n_tuples ++;
		if (n_tuples > APP_ARG_RX_MAX_TUPLES) {
			return -10;
		}
	}

	if (n_tuples == 0) {
		return -11;
	}
	return 0;
}

void app_print_usage(void)
{
	printf("%s\n", usage);
}

int app_get_nic_rx_queues_per_port(uint8_t port)
{
	uint32_t i, count;

	if (port >= APP_MAX_NIC_PORTS) {
		return -1;
	}

	count = 0;
	for (i = 0; i < APP_MAX_RX_QUEUES_PER_NIC_PORT; i ++) {
		if (app.nic_rx_queue_mask[port][i] == 1) {
			count ++;
		}
	}

	return count;
}

int app_get_lcore_for_nic_rx(uint8_t port, uint8_t queue, uint32_t *lcore_out)
{
	uint32_t lcore;

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
		uint32_t i;

		if (app.lcore_params[lcore].type != e_APP_LCORE_IO) {
			continue;
		}

		const size_t n_queues = RTE_MIN(lp->rx.n_nic_queues,
		                                RTE_DIM(lp->rx.nic_queues));
		for (i = 0; i < n_queues; i ++) {
			if ((lp->rx.nic_queues[i].port == port) &&
			    (lp->rx.nic_queues[i].queue == queue)) {
				*lcore_out = lcore;
				return 0;
			}
		}
	}

	return -1;
}

void app_print_params(void)
{
	unsigned port, queue, lcore, rule, i, j;

	/* Print NIC RX configuration */
	printf("NIC RX ports: ");
	for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
		uint32_t n_rx_queues = app_get_nic_rx_queues_per_port((uint8_t) port);

		if (n_rx_queues == 0) {
			continue;
		}

		printf("%u (", port);
		for (queue = 0; queue < APP_MAX_RX_QUEUES_PER_NIC_PORT; queue ++) {
			if (app.nic_rx_queue_mask[port][queue] == 1) {
				printf("%u ", queue);
			}
		}
		printf(")  ");
	}
	printf(";\n");

	/* Print I/O lcore RX params */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp->rx.n_nic_queues == 0)) {
			continue;
		}

		printf("I/O lcore %u (socket %u): ", lcore, rte_lcore_to_socket_id(lcore));

		printf("RX ports  ");
		for (i = 0; i < lp->rx.n_nic_queues; i ++) {
			printf("(%u, %u)  ",
				(unsigned) lp->rx.nic_queues[i].port,
				(unsigned) lp->rx.nic_queues[i].queue);
		}
		printf("; ");

		printf("Output rings  ");
		for (i = 0; i < lp->rx.n_rings; i ++) {
			printf("%p  ", lp->rx.rings[i]);
		}
		printf(";\n");
	}

	/* Print worker lcore RX params */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_flow *lp = &app.lcore_params[lcore].flow;

		if (app.lcore_params[lcore].type != e_APP_LCORE_FLOW) {
			continue;
		}

		printf("Flow lcore %u (socket %u)", lcore, rte_lcore_to_socket_id(lcore)
			);

		printf("Input rings  ");
		for (i = 0; i < lp->n_rings_in; i ++) {
			printf("%p  ", lp->rings_in[i]);
		}
		printf(";\n");
	}

	printf("\n");
}

#ifndef APP_ARG_FLOW_MAX_CHARS
#define APP_ARG_FLOW_MAX_CHARS     4096
#endif

#ifndef APP_ARG_FLOW_MAX_TUPLES
#define APP_ARG_FLOW_MAX_TUPLES    APP_MAX_FLOW_LCORES
#endif

static int
parse_arg_flow(const char *arg)
{
	const char *p = arg;
	uint32_t n_tuples;

	if (strnlen(arg, APP_ARG_FLOW_MAX_CHARS + 1) == APP_ARG_FLOW_MAX_CHARS + 1) {
		return -1;
	}

	n_tuples = 0;
	while (*p != 0) {
		struct app_lcore_params *lp;
		uint32_t lcore;

		errno = 0;
		lcore = strtoul(p, NULL, 0);
		if ((errno != 0)) {
			return -2;
		}

		/* Check and enable worker lcore */
		if (rte_lcore_is_enabled(lcore) == 0) {
			return -3;
		}

		if (lcore >= APP_MAX_LCORES) {
			return -4;
		}
		lp = &app.lcore_params[lcore];
		if (lp->type == e_APP_LCORE_IO || lp->type == e_APP_LCORE_DISSECTOR) {
			return -5;
		}
		lp->type = e_APP_LCORE_FLOW;

		n_tuples ++;
		if (n_tuples > APP_ARG_FLOW_MAX_TUPLES) {
			return -6;
		}

		p = strchr(p, ',');
		if (p == NULL) {
			break;
		}
		p ++;
	}

	if (n_tuples == 0) {
		return -7;
	}

	if ((n_tuples & (n_tuples - 1)) != 0) {
		return -8;
	}

	return 0;
}

/* Parse the argument given in the command line of the application */
int app_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{"rx", 1, 0, 0},
		{"flow", 1, 0, 0},
		{NULL, 0, 0, 0}
	};
	uint32_t arg_flow = 0;
	uint32_t arg_rx = 0;

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* long options */
		case 0:
			if (!strcmp(lgopts[option_index].name, "rx")) {
				arg_rx = 1;
				ret = 0;
				ret = parse_arg_rx(optarg);
				printf("arg_rx %d \n", arg_rx);
				if (ret) {
					printf("Incorrect value for --rx argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "flow")) {
				arg_flow = 1;
				ret = 0;
				ret = parse_arg_flow(optarg);
				printf("arg_flow %d \n", arg_flow);
				if (ret) {
					printf("Incorrect value for --flow argument (%d)\n", ret);
					return -1;
				}
			}
			break;

		default:
			return -1;
		}
	}

	/* Check that all mandatory arguments are provided */
	if ((arg_rx == 0) || (arg_flow == 0) ){
		printf("Not all mandatory arguments are present\n");
		return -1;
	}


	app.nic_rx_ring_size = APP_DEFAULT_NIC_RX_RING_SIZE;
	app.ring_rx_size = APP_DEFAULT_RING_RX_SIZE;

	app.burst_size_io_rx_read = APP_DEFAULT_BURST_SIZE_IO_RX_READ;
	app.burst_size_io_rx_write = APP_DEFAULT_BURST_SIZE_IO_RX_WRITE;
	app.burst_size_flow_read = APP_DEFAULT_BURST_SIZE_FLOW_READ;

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 0; /* reset getopt lib */
	app_print_params();
	return ret;
}
