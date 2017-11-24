#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "packet.h"
#include "dissector.h"

static void print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s: %s ", name, buf);
}

//将整数IP地址转换成字符串IP地址
char *int_to_str(const int ip, char *buf)
{
    sprintf(buf, "%u.%u.%u.%u",
        (unsigned char )*((char *)&ip + 0),
        (unsigned char )*((char *)&ip + 1),
        (unsigned char )*((char *)&ip + 2),
        (unsigned char )*((char *)&ip + 3));
    return buf;
}
void print_packet_info(packet_t *pkt)
{
	char src_ip[32],dst_ip[32];

	print_ethaddr("Src Mac", pkt->ehdr);
	print_ethaddr("Dst Mac", pkt->ehdr);
	putchar('\n');

    printf("src_ip: %s\n", int_to_str(pkt->ip_hdr->src_addr, src_ip));
    printf("src_ip: %s\n", int_to_str(pkt->ip_hdr->dst_addr, dst_ip));

    switch (pkt->ip_hdr->next_proto_id) {
		case IPPROTO_UDP:
			printf("udp src port %d dst port %d\n", rte_be_to_cpu_16(pkt->udp_hdr->src_port), rte_be_to_cpu_16(pkt->udp_hdr->dst_port));
			break;
		case IPPROTO_TCP:
			printf("tcp src port %d  dst port %d\n", rte_be_to_cpu_16(pkt->tcp_hdr->src_port), rte_be_to_cpu_16(pkt->tcp_hdr->dst_port));
			break;

		default:
			printf("Other Protocol\n");
			break;
		}
}


int dissect_packet(struct rte_mbuf *mbuf, packet_t *pkt)
{
	int ret = 1;
	/* 处理以太网头 */
	pkt->ehdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr* );

	/* 不是IPv4的数据包*/
	if (pkt->ehdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		return ret;
	}
	/* 处理IP头 */
	pkt->ip_hdr = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));

	 switch (pkt->ip_hdr->next_proto_id) {
	    case IPPROTO_UDP:
	    	pkt->udp_hdr = (struct udp_hdr *)((unsigned char *)pkt->ip_hdr +
	    	    						sizeof(struct ipv4_hdr));
	    	break;
	    case IPPROTO_TCP:
	    	pkt->tcp_hdr = (struct tcp_hdr *)((unsigned char *)pkt->ip_hdr +
	    						sizeof(struct ipv4_hdr));
		    break;

	    default:
	    	printf("Other Protocol \n");
	    	ret = 0;
	    	break;
	    }
	return ret;
}
