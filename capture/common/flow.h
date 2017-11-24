#ifndef FLOW_H_
#define FLOW_H_
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
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __attribute__((__packed__));

typedef struct ipv4_flow
{
    long   tabid;
    long   sys_reserved;
    timerId_t tid;
    uint32_t    sip;
    uint32_t    dip;
    uint16_t    sport;
    uint16_t    dport;
    uint8_t    proto;
    uint8_t    state:1;  // 0-dead flow, 1-alive flow.
    uint8_t    reserv:7; // reserved for other use.
    uint16_t    appid;
    char     ext_data[0]; // user can define your own data here!
} ipv4_flow_t;


// state of flow.
#define FLOW_DEAD   0
#define FLOW_ALIVE  1

typedef struct flow_tab
{
	long  tabid;
	long  sys_reserved; // system reserved and don't modify it!!!

	uint32_t    sip;
	uint32_t    dip;
	uint16_t    sport;
	uint16_t    dport;
	uint8_t    proto;
	uint8_t    state:1;  // 0-dead flow, 1-alive flow.
	uint8_t    reserv:7; // reserved for other use.
	uint16_t    appid;
	char     ext_data[0]; // user can define your own data here!
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

    union {
        struct ipv4_hdr * pipv4;
        struct {
			uint32_t sip_v4;
			uint32_t dip_v4;
        };
    };
} flow_para_t;
////////////////////////////////////////////////////////////////////////////////

#pragma pack()

////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////////////////////////////////////////
int  create_flowtab(int socketid);
void      delete_flowtab(int socketid);
int       get_flowtab_stat(int socketid, flow_tab_t *flow_tab);
////////////////////////////////////////////////////////////////////////////////
/*------------------------------------------------------------------------------
                            lock mode.
------------------------------------------------------------------------------*/
// create ipv4-flow key
ipv4_flow_t *create_flow_ipv4(int socketid, flow_para_t *para);

// create ipv4-flow
int create_flow_ipv4(int socketid, struct ipv4_5tuple *key);

// search ipv4-flow.
IPv4Flow_t *search_flow_ipv4(int socketid,struct ipv4_5tuple key);

// delete ipv4-flow.
void  del_flow_ipv4(int socketid, struct ipv4_5tuple key);


#ifdef __cplusplus
}
#endif

////////////////////////////////////////////////////////////////////////////////

#endif /* FLOW_H_ */
