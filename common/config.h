#ifndef CONFIG_H_
#define CONFIG_H_

/* Logical cores */
#ifndef APP_MAX_SOCKETS
#define APP_MAX_SOCKETS 2
#endif

#ifndef APP_MAX_LCORES
#define APP_MAX_LCORES       RTE_MAX_LCORE
#endif

#ifndef APP_MAX_NIC_PORTS
#define APP_MAX_NIC_PORTS    RTE_MAX_ETHPORTS
#endif

#ifndef APP_MAX_RX_QUEUES_PER_NIC_PORT
#define APP_MAX_RX_QUEUES_PER_NIC_PORT 128
#endif

#ifndef APP_MAX_IO_LCORES
#define APP_MAX_IO_LCORES 16
#endif
#if (APP_MAX_IO_LCORES > APP_MAX_LCORES)
#error "APP_MAX_IO_LCORES is too big"
#endif

#ifndef APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE
#define APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE 16
#endif

#ifndef APP_MAX_NIC_TX_PORTS_PER_IO_LCORE
#define APP_MAX_NIC_TX_PORTS_PER_IO_LCORE 16
#endif
#if (APP_MAX_NIC_TX_PORTS_PER_IO_LCORE > APP_MAX_NIC_PORTS)
#error "APP_MAX_NIC_TX_PORTS_PER_IO_LCORE too big"
#endif

#ifndef APP_MAX_FLOW_LCORES
#define APP_MAX_FLOW_LCORES 1
#endif
#if (APP_MAX_FLOW_LCORES > APP_MAX_LCORES)
#error "APP_MAX_FLOW_LCORES is too big"
#endif

#ifndef APP_MAX_FLOW_LCORES
#define APP_MAX_FLOW_LCORES 1
#endif

/* Mempools */
#ifndef APP_DEFAULT_MBUF_DATA_SIZE
#define APP_DEFAULT_MBUF_DATA_SIZE  RTE_MBUF_DEFAULT_BUF_SIZE
#endif

#ifndef APP_DEFAULT_MEMPOOL_BUFFERS
#define APP_DEFAULT_MEMPOOL_BUFFERS   8192 * 2
#endif

#ifndef APP_DEFAULT_MEMPOOL_CACHE_SIZE
#define APP_DEFAULT_MEMPOOL_CACHE_SIZE  256
#endif

/* LPM Tables */
#ifndef APP_MAX_LPM_RULES
#define APP_MAX_LPM_RULES 1024
#endif

/* NIC RX */
#ifndef APP_DEFAULT_NIC_RX_RING_SIZE
#define APP_DEFAULT_NIC_RX_RING_SIZE 1024
#endif

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#ifndef APP_DEFAULT_NIC_RX_PTHRESH
#define APP_DEFAULT_NIC_RX_PTHRESH  8
#endif

#ifndef APP_DEFAULT_NIC_RX_HTHRESH
#define APP_DEFAULT_NIC_RX_HTHRESH  8
#endif

#ifndef APP_DEFAULT_NIC_RX_WTHRESH
#define APP_DEFAULT_NIC_RX_WTHRESH  4
#endif

#ifndef APP_DEFAULT_NIC_RX_FREE_THRESH
#define APP_DEFAULT_NIC_RX_FREE_THRESH  64
#endif

#ifndef APP_DEFAULT_NIC_RX_DROP_EN
#define APP_DEFAULT_NIC_RX_DROP_EN 0
#endif

/* NIC TX */
#ifndef APP_DEFAULT_NIC_TX_RING_SIZE
#define APP_DEFAULT_NIC_TX_RING_SIZE 1024
#endif

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#ifndef APP_DEFAULT_NIC_TX_PTHRESH
#define APP_DEFAULT_NIC_TX_PTHRESH  36
#endif

#ifndef APP_DEFAULT_NIC_TX_HTHRESH
#define APP_DEFAULT_NIC_TX_HTHRESH  0
#endif

#ifndef APP_DEFAULT_NIC_TX_WTHRESH
#define APP_DEFAULT_NIC_TX_WTHRESH  0
#endif

#ifndef APP_DEFAULT_NIC_TX_FREE_THRESH
#define APP_DEFAULT_NIC_TX_FREE_THRESH  0
#endif

#ifndef APP_DEFAULT_NIC_TX_RS_THRESH
#define APP_DEFAULT_NIC_TX_RS_THRESH  0
#endif

/* Software Rings */
#ifndef APP_DEFAULT_RING_RX_SIZE
#define APP_DEFAULT_RING_RX_SIZE 1024
#endif

#ifndef APP_DEFAULT_RING_TX_SIZE
#define APP_DEFAULT_RING_TX_SIZE 1024
#endif

/* Bursts */
#ifndef APP_MBUF_ARRAY_SIZE
#define APP_MBUF_ARRAY_SIZE   512
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_RX_READ
#define APP_DEFAULT_BURST_SIZE_IO_RX_READ  16
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_RX_READ > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_RX_READ is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_RX_WRITE
#define APP_DEFAULT_BURST_SIZE_IO_RX_WRITE  16
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_RX_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_RX_WRITE is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_FLOW_READ
#define APP_DEFAULT_BURST_SIZE_FLOW_READ  16
#endif
#if ((2 * APP_DEFAULT_BURST_SIZE_FLOW_READ) > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_WORKER_READ is too big"
#endif

#define false               0
#define true                1
typedef int bool;

extern volatile bool force_quit;

enum app_lcore_type {
	e_APP_LCORE_DISABLED = 0,
	e_APP_LCORE_IO,
	e_APP_LCORE_FLOW,
	e_APP_LCORE_DISSECTOR
};

struct app_mbuf_array {
	struct rte_mbuf *array[APP_MBUF_ARRAY_SIZE];
	uint32_t n_mbufs;
};

struct app_lcore_params_io {
	/* I/O RX */
	struct {
		/* NIC*/
		struct {
			uint8_t port;
			uint8_t queue;
		} nic_queues[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
		uint32_t n_nic_queues;

		/* Rings*/
		struct rte_ring *rings[APP_MAX_FLOW_LCORES];
		uint32_t n_rings;

		/* Internal buffers */
		struct app_mbuf_array mbuf_in;
		struct app_mbuf_array mbuf_out[APP_MAX_FLOW_LCORES];

		uint8_t mbuf_out_flush[APP_MAX_FLOW_LCORES];

		/* Stats */
		uint32_t nic_queues_count[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
		uint32_t nic_queues_iters[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
		uint32_t rings_count[APP_MAX_FLOW_LCORES];
		uint32_t rings_iters[APP_MAX_FLOW_LCORES];
	} rx;
};

struct app_lcore_params_flow{
	/* Rings */
	struct rte_ring *rings_in[APP_MAX_IO_LCORES];
	uint32_t n_rings_in;

	struct app_mbuf_array mbuf_in;

	/* Stats */
	uint32_t rings_in_count[APP_MAX_IO_LCORES];
	uint32_t rings_in_iters[APP_MAX_IO_LCORES];
};

/* 解析处理队列*/
struct app_lcore_params_dissector {

};

struct app_lcore_params {
	union {
		struct app_lcore_params_io io;  //收包
		struct app_lcore_params_flow flow; //流管理
		struct app_lcore_params_dissector dissector; //解析器
	};
	enum app_lcore_type type; //逻辑核角色类型
	struct rte_mempool *pool; //内存池
} __rte_cache_aligned;


//总个APP配置结构，考虑到多核编程的性能，这个结构每个逻辑核共享，其中很多结构都是每个逻辑核一份
struct app_params {
	/* lcore */
	struct app_lcore_params lcore_params[APP_MAX_LCORES];
	/* NIC */
	uint8_t nic_rx_queue_mask[APP_MAX_NIC_PORTS][APP_MAX_RX_QUEUES_PER_NIC_PORT];
	/* mbuf pools */
	struct rte_mempool *pools[APP_MAX_SOCKETS];
	/* rings */
	uint32_t nic_rx_ring_size;
	uint32_t ring_rx_size;
	/* burst size */
	uint32_t burst_size_io_rx_read;
	uint32_t burst_size_io_rx_write;
	//一次从环形缓冲中提取多少数据
	uint32_t burst_size_flow_read;
} __rte_cache_aligned;

extern struct app_params app;

int app_parse_args(int argc, char **argv);
void app_print_params(void);
void app_print_usage(void);
int app_get_nic_rx_queues_per_port(uint8_t port);
int app_get_lcore_for_nic_rx(uint8_t port, uint8_t queue, uint32_t *lcore_out);
#endif /* CONFIG_H_ */
