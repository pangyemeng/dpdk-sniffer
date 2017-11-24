#ifndef PACKET_H_
#define PACKET_H_

typedef struct packet{
	struct ether_hdr *ehdr;
	struct ipv4_hdr *ip_hdr;
	struct tcp_hdr *tcp_hdr;
	struct udp_hdr *udp_hdr;
	struct rte_mbuf *mbuf;
    struct packet *next;            /**< next packet */
} packet_t;

#endif /* PACKET_H_ */
