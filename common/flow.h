#ifndef FLOW_H_
#define FLOW_H_

#include "../dissector/packet.h"

////////////////////////////////////////////////////////////////////////////////
#define FLOW_TYPE_V4    0 // flow v4

////////////////////////////////////////////////////////////////////////////////
// flag of create_flowtab
#define FLOW_TCP        0x01 // create tcp flow table.
#define FLOW_UDP        0x02 // create udp flow table.
#define FLOW_OTHER      0x04 // create other ip flow table.

// return value of create flow.
#define FLOW_NEW        0x01
#define FLOW_EXIST      0x02

// create/search mode.
#define FLAG_BY_IPHDR   0 // create/search ipflow by ipv4/ipv6 header.
#define FLAG_BY_5TUPLE  1 // create/search ipflow by sip/sport/dip/dport/proto.

////////////////////////////////////////////////////////////////////////////////

struct ipv4_5tuple {
	uint8_t  pad0;
	uint8_t  proto;
	uint16_t pad1;
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
} __attribute__((__packed__));

typedef struct ipv4_flow
{
    uint64_t   tabid;
    uint64_t   pkt_num;
//    timerId_t tid; //流超时
    uint32_t    sip;
    uint32_t    dip;
    uint16_t    sport;
    uint16_t    dport;
    uint8_t    proto;
    uint8_t    state:1;  // 0-dead flow, 1-alive flow.
    uint8_t    reserv:7; // reserved for other use.
    uint16_t    appid;
    packet_t * volatile pkt_queue; //目前紧按包接收的顺序进行连接。
    packet_t * volatile pkt_queue_head;
    packet_t * volatile last_pkt;
    char     ext_data[0]; // user can define your own data here!
}ipv4_flow_t;


// state of flow.
#define FLOW_DEAD   0
#define FLOW_ALIVE  1

typedef struct flow_tab
{
	uint32_t tab_size; // flow hash table size.
	uint32_t mem_cnt;  // max flow count.
	uint32_t ext_size; // user defined extended memory size.
	uint32_t life;     // flow life time.
	uint32_t flag;     // create-flag. CREAT_TCP/CREAT_UDP/CREAT_OTHER
	uint8_t type;     // 0-V4, 1-V6.
	uint8_t cpuid;    // specify one CPU to process with the flowtab.
	uint16_t reserved2;
	uint32_t tcp_flows;
//	TimeOut      func;  // flow timeout callback.
} flow_tab_t;

// flow para.
typedef struct flow_para
{
	uint8_t type:6;   // V4-0, V6-1.
	uint8_t inout:2;  // 0-upflow, 1-downflow.
	uint8_t proto;    // TCP/UDP/...
	uint16_t flag;     // create flag(CREAT_IPHDR/CREAT_5TUPLE).
	uint16_t sport;    // TCP/UDP sport.
	uint16_t dport;    // TCP/UDP dport.
	uint32_t sip_v4;	// TCP/UDP ip.
	uint32_t dip_v4;	// TCP/UDP ip.
} flow_para_t;
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////////////////////////////////////////
int  create_flowtab(int socketid);
void      delete_flowtab(int socketid);
int       get_flowtab_stat(int socketid, flow_tab_t *flow_tab);
// print ipv4-flow
void print_flow_tab_info(int socketid);
////////////////////////////////////////////////////////////////////////////////
/*------------------------------------------------------------------------------
                            lock mode.
------------------------------------------------------------------------------*/
void create_flow_para(struct ipv4_hdr *ipv4_hdr, flow_para_t *para);

// create ipv4-flow key
ipv4_flow_t *create_flow_ipv4(int socketid, flow_para_t *para, struct rte_mbuf *mbuf);

// search ipv4-flow.
ipv4_flow_t *search_flow_ipv4(int socketid, flow_para_t *para);

// delete ipv4-flow.
void  del_flow_ipv4(int socketid, flow_para_t *para);


#ifdef __cplusplus
}
#endif

////////////////////////////////////////////////////////////////////////////////

#endif /* FLOW_H_ */
